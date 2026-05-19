package acme

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"portlyn/internal/domain"
	"portlyn/internal/secureconfig"
)

type CertMagicStorage struct {
	db           *gorm.DB
	lockTTL      time.Duration
	renewEvery   time.Duration
	dataSecrets  [][]byte
	owners       map[string]string
	ownerCancels map[string]context.CancelFunc
	mu           sync.Mutex
}

func NewCertMagicStorage(db *gorm.DB, lockTTL time.Duration, dataSecrets []string) *CertMagicStorage {
	if lockTTL <= 0 {
		lockTTL = 30 * time.Second
	}
	normalized := make([][]byte, 0, len(dataSecrets))
	for _, value := range dataSecrets {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		normalized = append(normalized, []byte(trimmed))
	}
	return &CertMagicStorage{
		db:           db,
		lockTTL:      lockTTL,
		renewEvery:   lockTTL / 3,
		dataSecrets:  normalized,
		owners:       make(map[string]string),
		ownerCancels: make(map[string]context.CancelFunc),
	}
}

func (s *CertMagicStorage) Store(ctx context.Context, key string, value []byte) error {
	key = cleanKey(key)
	storedValue := append([]byte(nil), value...)
	if isCertMagicPrivateKeyPath(key) && len(s.dataSecrets) > 0 && !secureconfig.IsEncryptedBytesV1(storedValue) {
		encrypted, err := secureconfig.EncryptBytesV1(s.dataSecrets[0], storedValue)
		if err != nil {
			return err
		}
		storedValue = encrypted
	}
	item := domain.DistributedKV{
		Bucket:     "certmagic",
		Key:        key,
		Value:      storedValue,
		ModifiedAt: time.Now().UTC(),
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("bucket = ? AND key = ?", item.Bucket, item.Key).Delete(&domain.DistributedKV{}).Error; err != nil {
			return err
		}
		return tx.Create(&item).Error
	})
}

func (s *CertMagicStorage) Load(ctx context.Context, key string) ([]byte, error) {
	key = cleanKey(key)
	var item domain.DistributedKV
	err := s.db.WithContext(ctx).Where("bucket = ? AND key = ?", "certmagic", key).First(&item).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fs.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	if isCertMagicPrivateKeyPath(key) && secureconfig.IsEncryptedBytesV1(item.Value) {
		plaintext, decryptErr := secureconfig.DecryptBytesV1WithSecrets(s.dataSecrets, item.Value)
		if decryptErr != nil {
			return nil, decryptErr
		}
		return plaintext, nil
	}
	return append([]byte(nil), item.Value...), nil
}

func (s *CertMagicStorage) Delete(ctx context.Context, key string) error {
	key = cleanKey(key)
	return s.db.WithContext(ctx).
		Where("bucket = ? AND (key = ? OR key LIKE ?)", "certmagic", key, key+"/%").
		Delete(&domain.DistributedKV{}).Error
}

func (s *CertMagicStorage) Exists(ctx context.Context, key string) bool {
	var count int64
	_ = s.db.WithContext(ctx).
		Model(&domain.DistributedKV{}).
		Where("bucket = ? AND (key = ? OR key LIKE ?)", "certmagic", cleanKey(key), cleanKey(key)+"/%").
		Count(&count).Error
	return count > 0
}

func (s *CertMagicStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	prefix = cleanKey(prefix)
	var rows []domain.DistributedKV
	if err := s.db.WithContext(ctx).
		Where("bucket = ? AND (key = ? OR key LIKE ?)", "certmagic", prefix, prefix+"/%").
		Order("key asc").
		Find(&rows).Error; err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(rows))
	seen := make(map[string]struct{})
	for _, row := range rows {
		if recursive {
			keys = append(keys, row.Key)
			continue
		}
		relative := strings.TrimPrefix(row.Key, prefix)
		relative = strings.TrimPrefix(relative, "/")
		if relative == "" {
			keys = append(keys, row.Key)
			continue
		}
		head := strings.Split(relative, "/")[0]
		candidate := prefix
		if head != "" {
			candidate = path.Join(prefix, head)
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		keys = append(keys, candidate)
	}
	if len(keys) == 0 {
		return nil, fs.ErrNotExist
	}
	return keys, nil
}

func (s *CertMagicStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	key = cleanKey(key)
	var exact domain.DistributedKV
	err := s.db.WithContext(ctx).Where("bucket = ? AND key = ?", "certmagic", key).First(&exact).Error
	if err == nil {
		return certmagic.KeyInfo{
			Key:        key,
			Modified:   exact.ModifiedAt,
			Size:       int64(len(exact.Value)),
			IsTerminal: true,
		}, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return certmagic.KeyInfo{}, err
	}
	if s.Exists(ctx, key) {
		return certmagic.KeyInfo{Key: key, IsTerminal: false}, nil
	}
	return certmagic.KeyInfo{}, fs.ErrNotExist
}

func (s *CertMagicStorage) Lock(ctx context.Context, name string) error {
	for {
		ok, err := s.tryAcquire(ctx, cleanKey(name))
		if err != nil {
			return err
		}
		if ok {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (s *CertMagicStorage) Unlock(ctx context.Context, name string) error {
	name = cleanKey(name)

	s.mu.Lock()
	owner := s.owners[name]
	cancel := s.ownerCancels[name]
	delete(s.owners, name)
	delete(s.ownerCancels, name)
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if owner == "" {
		return nil
	}
	return s.db.WithContext(ctx).Where("name = ? AND owner = ?", name, owner).Delete(&domain.DistributedLock{}).Error
}

func (s *CertMagicStorage) RenewLockLease(ctx context.Context, lockKey string, leaseDuration time.Duration) error {
	s.mu.Lock()
	owner := s.owners[cleanKey(lockKey)]
	s.mu.Unlock()
	if owner == "" {
		return nil
	}
	if leaseDuration <= 0 {
		leaseDuration = s.lockTTL
	}
	return s.db.WithContext(ctx).
		Model(&domain.DistributedLock{}).
		Where("name = ? AND owner = ?", cleanKey(lockKey), owner).
		Update("expires_at", time.Now().UTC().Add(leaseDuration)).Error
}

func (s *CertMagicStorage) tryAcquire(ctx context.Context, name string) (bool, error) {
	owner := randomOwner()
	acquired := false

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := time.Now().UTC()
		if err := tx.Where("expires_at <= ?", now).Delete(&domain.DistributedLock{}).Error; err != nil {
			return err
		}

		lock := domain.DistributedLock{
			Name:      name,
			Owner:     owner,
			ExpiresAt: now.Add(s.lockTTL),
		}
		result := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "name"}},
			DoNothing: true,
		}).Create(&lock)
		if result.Error != nil {
			return result.Error
		}
		acquired = result.RowsAffected > 0
		return nil
	})
	if err != nil {
		return false, err
	}
	if !acquired {
		return false, nil
	}

	s.startLease(name, owner)
	return true, nil
}

func (s *CertMagicStorage) startLease(name, owner string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if cancel, ok := s.ownerCancels[name]; ok {
		cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.owners[name] = owner
	s.ownerCancels[name] = cancel

	go func() {
		ticker := time.NewTicker(s.renewEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = s.db.WithContext(context.Background()).
					Model(&domain.DistributedLock{}).
					Where("name = ? AND owner = ?", name, owner).
					Update("expires_at", time.Now().UTC().Add(s.lockTTL)).Error
			}
		}
	}()
}

func (s *CertMagicStorage) MigrateSensitiveValues(ctx context.Context) (int, error) {
	if len(s.dataSecrets) == 0 {
		return 0, nil
	}
	var rows []domain.DistributedKV
	if err := s.db.WithContext(ctx).Where("bucket = ?", "certmagic").Find(&rows).Error; err != nil {
		return 0, err
	}
	updated := 0
	for _, row := range rows {
		if !isCertMagicPrivateKeyPath(row.Key) || secureconfig.IsEncryptedBytesV1(row.Value) {
			continue
		}
		encrypted, err := secureconfig.EncryptBytesV1(s.dataSecrets[0], row.Value)
		if err != nil {
			return updated, err
		}
		if err := s.db.WithContext(ctx).Model(&domain.DistributedKV{}).Where("id = ?", row.ID).Updates(map[string]any{
			"value":       encrypted,
			"modified_at": time.Now().UTC(),
		}).Error; err != nil {
			return updated, err
		}
		updated++
	}
	return updated, nil
}

func isCertMagicPrivateKeyPath(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	switch {
	case strings.HasSuffix(key, ".key"):
		return true
	case strings.Contains(key, "/private/"):
		return true
	case strings.Contains(key, "siteprivatekey"):
		return true
	case strings.Contains(key, "site_private_key"):
		return true
	default:
		return false
	}
}

func cleanKey(key string) string {
	return strings.Trim(strings.ReplaceAll(key, "\\", "/"), "/")
}

func randomOwner() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(buf)
}

var _ certmagic.Storage = (*CertMagicStorage)(nil)
