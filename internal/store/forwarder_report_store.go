package store

import (
	"context"
	"encoding/json"
	"time"

	"gorm.io/gorm"

	"portlyn/internal/domain"
)

const (
	forwarderReportBucket = "proxy"
	forwarderReportKey    = "untrusted_forwarders"
)

type ForwarderReportStore struct {
	db *gorm.DB
}

func NewForwarderReportStore(db *gorm.DB) *ForwarderReportStore {
	return &ForwarderReportStore{db: db}
}

func (s *ForwarderReportStore) Save(ctx context.Context, report domain.ForwarderReport) error {
	value, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("bucket = ? AND key = ?", forwarderReportBucket, forwarderReportKey).Delete(&domain.DistributedKV{}).Error; err != nil {
			return err
		}
		return tx.Create(&domain.DistributedKV{
			Bucket:     forwarderReportBucket,
			Key:        forwarderReportKey,
			Value:      value,
			ModifiedAt: time.Now().UTC(),
		}).Error
	})
}

func (s *ForwarderReportStore) Load(ctx context.Context) (*domain.ForwarderReport, error) {
	var row domain.DistributedKV
	if err := s.db.WithContext(ctx).Where("bucket = ? AND key = ?", forwarderReportBucket, forwarderReportKey).Limit(1).Find(&row).Error; err != nil {
		return nil, err
	}
	if row.ID == 0 {
		return nil, nil
	}
	var report domain.ForwarderReport
	if err := json.Unmarshal(row.Value, &report); err != nil {
		return nil, err
	}
	return &report, nil
}
