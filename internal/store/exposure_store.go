package store

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"portlyn/internal/domain"
)

type ExposureReportStore struct {
	db *gorm.DB
}

func NewExposureReportStore(db *gorm.DB) *ExposureReportStore {
	return &ExposureReportStore{db: db}
}

func (s *ExposureReportStore) Upsert(ctx context.Context, report *domain.ServiceExposureReport) error {
	now := time.Now().UTC()
	report.UpdatedAt = now
	var existing domain.ServiceExposureReport
	err := s.db.WithContext(ctx).Where("service_id = ?", report.ServiceID).First(&existing).Error
	if err == nil {
		report.ID = existing.ID
		report.CreatedAt = existing.CreatedAt
		return s.db.WithContext(ctx).Save(report).Error
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		report.CreatedAt = now
		return s.db.WithContext(ctx).Create(report).Error
	}
	return err
}

func (s *ExposureReportStore) List(ctx context.Context) ([]domain.ServiceExposureReport, error) {
	var items []domain.ServiceExposureReport
	err := s.db.WithContext(ctx).Order("service_id asc").Find(&items).Error
	return items, err
}

func (s *ExposureReportStore) DeleteByServiceID(ctx context.Context, serviceID uint) error {
	return s.db.WithContext(ctx).Where("service_id = ?", serviceID).Delete(&domain.ServiceExposureReport{}).Error
}

func (s *ExposureReportStore) GetByServiceID(ctx context.Context, serviceID uint) (*domain.ServiceExposureReport, error) {
	var item domain.ServiceExposureReport
	err := s.db.WithContext(ctx).Where("service_id = ?", serviceID).First(&item).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}
