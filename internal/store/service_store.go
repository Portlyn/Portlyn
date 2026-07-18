package store

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"portlyn/internal/domain"
)

type ServiceStore struct {
	db *gorm.DB
}

func NewServiceStore(db *gorm.DB) *ServiceStore {
	return &ServiceStore{db: db}
}

func (s *ServiceStore) List(ctx context.Context) ([]domain.Service, error) {
	var items []domain.Service
	err := s.db.WithContext(ctx).Preload("Domain").Preload("ServiceGroups").Preload("Node").Order("id asc").Find(&items).Error
	return items, err
}

func (s *ServiceStore) Create(ctx context.Context, item *domain.Service) error {
	return s.db.WithContext(ctx).Create(item).Error
}

func (s *ServiceStore) Count(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&domain.Service{}).Count(&count).Error
	return count, err
}

func (s *ServiceStore) GetByID(ctx context.Context, id uint) (*domain.Service, error) {
	var item domain.Service
	err := s.db.WithContext(ctx).Preload("Domain").Preload("ServiceGroups").Preload("Node").First(&item, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *ServiceStore) Update(ctx context.Context, item *domain.Service) error {
	return s.db.WithContext(ctx).Omit("Domain", "ServiceGroups.*", "Node").Save(item).Error
}

func (s *ServiceStore) Delete(ctx context.Context, id uint) error {
	result := s.db.WithContext(ctx).Delete(&domain.Service{}, id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *ServiceStore) ReplaceServiceGroups(ctx context.Context, serviceID uint, groupIDs []uint) error {
	service := &domain.Service{ID: serviceID}
	groups := make([]domain.ServiceGroup, 0, len(groupIDs))
	for _, id := range groupIDs {
		groups = append(groups, domain.ServiceGroup{ID: id})
	}
	return s.db.WithContext(ctx).Model(service).Association("ServiceGroups").Replace(groups)
}

func (s *ServiceStore) FindByRoute(ctx context.Context, domainID uint, subdomain, path string) (*domain.Service, error) {
	var item domain.Service
	err := s.db.WithContext(ctx).
		Preload("Domain").
		Preload("ServiceGroups").
		Preload("Node").
		Where("domain_id = ? AND subdomain = ? AND path = ?", domainID, subdomain, path).
		First(&item).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *ServiceStore) ListByDomainID(ctx context.Context, domainID uint) ([]domain.Service, error) {
	var items []domain.Service
	err := s.db.WithContext(ctx).
		Preload("Domain").
		Preload("ServiceGroups").
		Preload("Node").
		Where("domain_id = ?", domainID).
		Order("id asc").
		Find(&items).Error
	return items, err
}
