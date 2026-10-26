package store

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"portlyn/internal/domain"
)

type CertificateStore struct {
	db *gorm.DB
}

func NewCertificateStore(db *gorm.DB) *CertificateStore {
	return &CertificateStore{db: db}
}

func (s *CertificateStore) List(ctx context.Context) ([]domain.Certificate, error) {
	var items []domain.Certificate
	err := s.db.WithContext(ctx).
		Preload("Domain").
		Preload("SANs").
		Preload("DNSProvider").
		Order("id asc").
		Find(&items).Error
	return items, err
}

func (s *CertificateStore) Create(ctx context.Context, item *domain.Certificate) error {
	return s.db.WithContext(ctx).Create(item).Error
}

func (s *CertificateStore) Count(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&domain.Certificate{}).Count(&count).Error
	return count, err
}

func (s *CertificateStore) GetByID(ctx context.Context, id uint) (*domain.Certificate, error) {
	var item domain.Certificate
	err := s.db.WithContext(ctx).
		Preload("Domain").
		Preload("SANs").
		Preload("DNSProvider").
		First(&item, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *CertificateStore) Update(ctx context.Context, item *domain.Certificate) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.WithContext(ctx).Omit("Domain", "DNSProvider", "SANs").Save(item).Error; err != nil {
			return err
		}
		if err := tx.WithContext(ctx).Where("certificate_id = ?", item.ID).Delete(&domain.CertificateSAN{}).Error; err != nil {
			return err
		}
		if len(item.SANs) == 0 {
			return nil
		}
		for i := range item.SANs {
			item.SANs[i].ID = 0
			item.SANs[i].CertificateID = item.ID
		}
		return tx.WithContext(ctx).Create(&item.SANs).Error
	})
}

func (s *CertificateStore) Delete(ctx context.Context, id uint) error {
	result := s.db.WithContext(ctx).Delete(&domain.Certificate{}, id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *CertificateStore) UpdateRetryState(ctx context.Context, id uint, failureCount int, nextAttemptAt *time.Time) error {
	return s.db.WithContext(ctx).
		Model(&domain.Certificate{}).
		Where("id = ?", id).
		UpdateColumns(map[string]any{"failure_count": failureCount, "next_attempt_at": nextAttemptAt}).Error
}

func (s *CertificateStore) ListPending(ctx context.Context, dueBy time.Time, limit int) ([]domain.Certificate, error) {
	if limit <= 0 {
		limit = 10
	}
	var items []domain.Certificate
	err := s.db.WithContext(ctx).
		Preload("Domain").
		Preload("SANs").
		Preload("DNSProvider").
		Where("status = ?", domain.CertificateStatusPending).
		Where("next_attempt_at IS NULL OR next_attempt_at <= ?", dueBy).
		Order("id asc").
		Limit(limit).
		Find(&items).Error
	return items, err
}

func (s *CertificateStore) ListExpiringBefore(ctx context.Context, before, dueBy time.Time) ([]domain.Certificate, error) {
	var items []domain.Certificate
	err := s.db.WithContext(ctx).
		Preload("Domain").
		Preload("SANs").
		Preload("DNSProvider").
		Where("expires_at <= ?", before).
		Where("next_attempt_at IS NULL OR next_attempt_at <= ?", dueBy).
		Order("expires_at asc").
		Find(&items).Error
	return items, err
}
