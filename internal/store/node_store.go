package store

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"portlyn/internal/domain"
)

var errEnrollmentTokenClaimed = errors.New("enrollment token already claimed")

type NodeStore struct {
	db *gorm.DB
}

func NewNodeStore(db *gorm.DB) *NodeStore {
	return &NodeStore{db: db}
}

func (s *NodeStore) List(ctx context.Context) ([]domain.Node, error) {
	var nodes []domain.Node
	err := s.db.WithContext(ctx).Order("id asc").Find(&nodes).Error
	return nodes, err
}

func (s *NodeStore) Create(ctx context.Context, node *domain.Node) error {
	return s.db.WithContext(ctx).Create(node).Error
}

// Claims the token and creates the node in one transaction: a failure leaves the
// token usable and no partial node behind. finalize runs after the insert, once
// the node has an ID. Returns false if a single-use token was already claimed.
func (s *NodeStore) EnrollWithToken(ctx context.Context, node *domain.Node, tokenID uint, singleUse bool, usedAt time.Time, finalize func(*domain.Node)) (bool, error) {
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if singleUse {
			result := tx.Model(&domain.NodeEnrollmentToken{}).
				Where("id = ? AND active = ? AND used_at IS NULL", tokenID, true).
				Updates(map[string]any{"active": false, "used_at": usedAt})
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return errEnrollmentTokenClaimed
			}
		}
		if err := tx.Create(node).Error; err != nil {
			return err
		}
		if finalize != nil {
			finalize(node)
			if err := tx.Save(node).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if errors.Is(err, errEnrollmentTokenClaimed) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *NodeStore) Count(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&domain.Node{}).Count(&count).Error
	return count, err
}

func (s *NodeStore) GetByID(ctx context.Context, id uint) (*domain.Node, error) {
	var node domain.Node
	err := s.db.WithContext(ctx).First(&node, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &node, nil
}

func (s *NodeStore) FindByName(ctx context.Context, name string) (*domain.Node, error) {
	var nodes []domain.Node
	if err := s.db.WithContext(ctx).Where("name = ?", name).Limit(2).Find(&nodes).Error; err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 0:
		return nil, ErrNotFound
	case 1:
		return &nodes[0], nil
	default:
		return nil, ErrConflict
	}
}

func (s *NodeStore) GetByHeartbeatTokenHash(ctx context.Context, tokenHash string) (*domain.Node, error) {
	var node domain.Node
	err := s.db.WithContext(ctx).Where("heartbeat_token_hash = ?", tokenHash).First(&node).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &node, nil
}

func (s *NodeStore) Update(ctx context.Context, node *domain.Node) error {
	return s.db.WithContext(ctx).Save(node).Error
}

func (s *NodeStore) UpdateHeartbeat(ctx context.Context, node *domain.Node) error {
	return s.db.WithContext(ctx).Save(node).Error
}

func (s *NodeStore) Delete(ctx context.Context, id uint) error {
	result := s.db.WithContext(ctx).Delete(&domain.Node{}, id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}
