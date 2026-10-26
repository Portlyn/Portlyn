package acme

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"portlyn/internal/domain"
	"portlyn/internal/store"
)

type CertificateRenewer interface {
	SyncCertificate(ctx context.Context, item *domain.Certificate) (*domain.Certificate, error)
}

const syncTimeout = 10 * time.Minute

type AcmeWorker struct {
	store       CertificateStore
	metaStore   *store.CertificateStore
	renewer     CertificateRenewer
	interval    time.Duration
	renewWithin time.Duration
	logger      *slog.Logger
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	now         func() time.Time
}

func NewAcmeWorker(store CertificateStore, metaStore *store.CertificateStore, renewer CertificateRenewer, interval, renewWithin time.Duration, logger *slog.Logger) *AcmeWorker {
	if interval <= 0 {
		interval = time.Minute
	}
	if renewWithin <= 0 {
		renewWithin = 30 * 24 * time.Hour
	}
	return &AcmeWorker{
		store:       store,
		metaStore:   metaStore,
		renewer:     renewer,
		interval:    interval,
		renewWithin: renewWithin,
		logger:      logger,
		now:         time.Now,
	}
}

func (w *AcmeWorker) Start(ctx context.Context) {
	if w.metaStore == nil || w.renewer == nil {
		return
	}
	if w.cancel != nil {
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.wg.Add(1)
	go w.loop(runCtx)
}

func (w *AcmeWorker) Stop() {
	if w.cancel != nil {
		w.cancel()
		w.wg.Wait()
	}
}

func (w *AcmeWorker) loop(ctx context.Context) {
	defer w.wg.Done()
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		w.runOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *AcmeWorker) runOnce(ctx context.Context) {
	now := w.now().UTC()
	pending, err := w.metaStore.ListPending(ctx, now, 32)
	if err != nil {
		if w.logger != nil {
			w.logger.Error("list pending certificates failed", "error", err)
		}
		return
	}
	for i := range pending {
		w.sync(ctx, &pending[i], "pending certificate sync failed")
	}

	expiring, err := w.metaStore.ListExpiringBefore(ctx, now.Add(w.renewWithin), now)
	if err != nil {
		if w.logger != nil {
			w.logger.Error("list expiring certificates failed", "error", err)
		}
		return
	}
	for i := range expiring {
		if !expiring[i].IsAutoRenew {
			continue
		}
		w.sync(ctx, &expiring[i], "expiring certificate sync failed")
	}
}

func (w *AcmeWorker) sync(ctx context.Context, item *domain.Certificate, failureMessage string) {
	syncCtx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	if _, err := w.renewer.SyncCertificate(syncCtx, item); err != nil && w.logger != nil {
		w.logger.Error(failureMessage, "certificate_id", item.ID, "error", err)
	}
}
