package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	stdhttp "net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"portlyn/internal/domain"
)

const (
	DropNewest    = "drop_newest"
	DropOldest    = "drop_oldest"
	SyncFallback  = "sync_fallback"
	BlockProducer = "block"
)

type AuditEvent struct {
	Timestamp    time.Time `json:"timestamp"`
	RequestID    string    `json:"request_id"`
	UserID       *uint     `json:"user_id,omitempty"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceID   *uint     `json:"resource_id,omitempty"`
	Method       string    `json:"method"`
	Host         string    `json:"host"`
	Path         string    `json:"path"`
	StatusCode   int       `json:"status_code"`
	LatencyMs    int64     `json:"latency_ms"`
	RemoteAddr   string    `json:"remote_addr"`
	UserAgent    string    `json:"user_agent"`
	Details      any       `json:"details,omitempty"`
}

type AuditSink interface {
	WriteEvent(ctx context.Context, ev AuditEvent) error
}

type AsyncSink struct {
	store         AuditBatchWriter
	logger        *slog.Logger
	events        chan AuditEvent
	dropPolicy    string
	batchSize     int
	flushInterval time.Duration
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

type HTTPAccessEvent struct {
	Request      *stdhttp.Request
	UserID       *uint
	Action       string
	ResourceType string
	ResourceID   *uint
	StatusCode   int
	Latency      time.Duration
	Details      any
	RequestID    string
	RemoteAddr   string
	UserAgent    string
	Method       string
	Host         string
	Path         string
}

type Logger struct {
	sink       AuditSink
	dispatcher *WebhookDispatcher
}

type AuditBatchWriter interface {
	Create(ctx context.Context, item *domain.AuditLog) error
	CreateBatch(ctx context.Context, items []domain.AuditLog) error
}

func NewAsyncSink(store AuditBatchWriter, bufferSize, batchSize int, flushInterval time.Duration, dropPolicy string, baseLogger *slog.Logger) *AsyncSink {
	if bufferSize <= 0 {
		bufferSize = 1024
	}
	if batchSize <= 0 {
		batchSize = 128
	}
	if flushInterval <= 0 {
		flushInterval = 250 * time.Millisecond
	}
	if dropPolicy == "" {
		dropPolicy = SyncFallback
	}

	ctx, cancel := context.WithCancel(context.Background())
	sink := &AsyncSink{
		store:         store,
		logger:        baseLogger,
		events:        make(chan AuditEvent, bufferSize),
		dropPolicy:    dropPolicy,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		cancel:        cancel,
	}
	sink.wg.Add(1)
	go sink.run(ctx)
	return sink
}

func (s *AsyncSink) Close() {
	s.cancel()
	s.wg.Wait()
}

func (s *AsyncSink) WriteEvent(ctx context.Context, ev AuditEvent) error {
	switch s.dropPolicy {
	case BlockProducer:
		select {
		case s.events <- ev:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	case DropNewest:
		select {
		case s.events <- ev:
		default:
			s.logDrop(ev, "drop_newest")
		}
		return nil
	case DropOldest:
		select {
		case s.events <- ev:
		default:
			select {
			case <-s.events:
			default:
			}
			select {
			case s.events <- ev:
			default:
				s.logDrop(ev, "drop_oldest")
			}
		}
		return nil
	case SyncFallback:
		fallthrough
	default:
		select {
		case s.events <- ev:
			return nil
		default:
			return s.store.Create(ctx, toAuditLog(ev))
		}
	}
}

func (s *AsyncSink) run(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	buffer := make([]domain.AuditLog, 0, s.batchSize)
	flush := func() {
		if len(buffer) == 0 {
			return
		}
		batch := append([]domain.AuditLog(nil), buffer...)
		buffer = buffer[:0]
		if err := s.store.CreateBatch(context.Background(), batch); err != nil && s.logger != nil {
			s.logger.Error("failed to persist audit log batch", "error", err, "count", len(batch))
		}
	}

	for {
		select {
		case <-ctx.Done():
			drain := true
			for drain {
				select {
				case ev := <-s.events:
					buffer = append(buffer, *toAuditLog(ev))
				default:
					drain = false
				}
			}
			flush()
			return
		case ev := <-s.events:
			buffer = append(buffer, *toAuditLog(ev))
			if len(buffer) >= s.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (s *AsyncSink) logDrop(ev AuditEvent, reason string) {
	if s.logger != nil {
		s.logger.Warn("audit event dropped", "action", ev.Action, "resource_type", ev.ResourceType, "reason", reason)
	}
}

func NewLogger(sink AuditSink) *Logger {
	return &Logger{sink: sink}
}

func (l *Logger) SetWebhookDispatcher(dispatcher *WebhookDispatcher) {
	l.dispatcher = dispatcher
}

func (l *Logger) Log(ctx context.Context, userID *uint, action, resourceType string, resourceID *uint, details any) error {
	return l.write(ctx, AuditEvent{
		Timestamp:    time.Now().UTC(),
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      details,
	})
}

func (l *Logger) LogRequest(ctx context.Context, r *stdhttp.Request, userID *uint, action, resourceType string, resourceID *uint, details any) error {
	return l.write(ctx, AuditEvent{
		Timestamp:    time.Now().UTC(),
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		RemoteAddr:   r.RemoteAddr,
		UserAgent:    r.UserAgent(),
		Method:       r.Method,
		Host:         r.Host,
		Path:         r.URL.Path,
		Details:      details,
	})
}

func (l *Logger) LogHTTPAccess(ctx context.Context, event HTTPAccessEvent) error {
	requestID := event.RequestID
	remoteAddr := event.RemoteAddr
	userAgent := event.UserAgent
	method := event.Method
	host := event.Host
	path := event.Path

	if event.Request != nil {
		if requestID == "" {
			requestID = middleware.GetReqID(event.Request.Context())
		}
		if remoteAddr == "" {
			remoteAddr = event.Request.RemoteAddr
		}
		if userAgent == "" {
			userAgent = event.Request.UserAgent()
		}
		if method == "" {
			method = event.Request.Method
		}
		if host == "" {
			host = event.Request.Host
		}
		if path == "" && event.Request.URL != nil {
			path = event.Request.URL.Path
		}
	}

	return l.write(ctx, AuditEvent{
		Timestamp:    time.Now().UTC(),
		RequestID:    requestID,
		UserID:       event.UserID,
		Action:       event.Action,
		ResourceType: event.ResourceType,
		ResourceID:   event.ResourceID,
		Method:       method,
		Host:         host,
		Path:         path,
		StatusCode:   event.StatusCode,
		LatencyMs:    event.Latency.Milliseconds(),
		RemoteAddr:   remoteAddr,
		UserAgent:    userAgent,
		Details:      event.Details,
	})
}

func (l *Logger) write(ctx context.Context, ev AuditEvent) error {
	if l.dispatcher != nil {
		details, _ := ev.Details.(map[string]any)
		l.dispatcher.Dispatch(ctx, *toAuditLog(ev), details)
	}
	return l.sink.WriteEvent(ctx, ev)
}

func toAuditLog(ev AuditEvent) *domain.AuditLog {
	details := ""
	if ev.Details != nil {
		if payload, err := json.Marshal(ev.Details); err == nil {
			details = string(payload)
		}
	}
	return &domain.AuditLog{
		Timestamp:    ev.Timestamp,
		RequestID:    ev.RequestID,
		UserID:       ev.UserID,
		Action:       ev.Action,
		ResourceType: ev.ResourceType,
		ResourceID:   ev.ResourceID,
		Method:       ev.Method,
		Host:         ev.Host,
		Path:         ev.Path,
		StatusCode:   ev.StatusCode,
		LatencyMs:    ev.LatencyMs,
		RemoteAddr:   ev.RemoteAddr,
		UserAgent:    ev.UserAgent,
		Details:      details,
	}
}
