package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"

	"portlyn/internal/domain"
	"portlyn/internal/secureconfig"
)

type CertificateMeta struct {
	Domain    string    `json:"domain"`
	IssuerKey string    `json:"issuer_key"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	UpdatedAt time.Time `json:"updated_at"`
}

type CertificateStore interface {
	GetCertificate(ctx context.Context, domain string) (*tls.Certificate, error)
	StoreCertificate(ctx context.Context, domain string, cert *tls.Certificate) error
	ListExpiringCertificates(ctx context.Context, within time.Duration) ([]CertificateMeta, error)
}

type DBCertificateStore struct {
	db          *gorm.DB
	dataSecrets [][]byte
}

func NewDBCertificateStore(db *gorm.DB, dataSecrets []string) *DBCertificateStore {
	normalized := make([][]byte, 0, len(dataSecrets))
	for _, value := range dataSecrets {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		normalized = append(normalized, []byte(trimmed))
	}
	return &DBCertificateStore{db: db, dataSecrets: normalized}
}

func (s *DBCertificateStore) GetCertificate(ctx context.Context, domainName string) (*tls.Certificate, error) {
	var item domain.StoredTLSCertificate
	err := s.db.WithContext(ctx).Where("domain = ?", normalizeDomain(domainName)).First(&item).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, gorm.ErrRecordNotFound
	}
	if err != nil {
		return nil, err
	}

	privateKey := item.PrivateKey
	if secureconfig.IsEncryptedBytes(item.PrivateKey) {
		privateKey, err = secureconfig.DecryptBytesAuto(s.dataSecrets, item.PrivateKey)
		if err != nil {
			return nil, err
		}
	}

	pair, err := tls.X509KeyPair(item.Certificate, privateKey)
	if err != nil {
		return nil, err
	}
	if len(pair.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err == nil {
			pair.Leaf = leaf
		}
	}
	return &pair, nil
}

func (s *DBCertificateStore) StoreCertificate(ctx context.Context, domainName string, cert *tls.Certificate) error {
	certPEM, keyPEM, notBefore, notAfter, err := marshalCertificate(cert)
	if err != nil {
		return err
	}
	if len(s.dataSecrets) > 0 && !secureconfig.IsEncryptedBytes(keyPEM) {
		encryptedKey, encryptErr := secureconfig.EncryptBytesV2(s.dataSecrets[0], keyPEM)
		if encryptErr != nil {
			return encryptErr
		}
		keyPEM = encryptedKey
	}

	var existing domain.StoredTLSCertificate
	err = s.db.WithContext(ctx).Where("domain = ?", normalizeDomain(domainName)).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return s.db.WithContext(ctx).Create(&domain.StoredTLSCertificate{
			Domain:      normalizeDomain(domainName),
			IssuerKey:   "",
			Certificate: certPEM,
			PrivateKey:  keyPEM,
			NotBefore:   notBefore,
			NotAfter:    notAfter,
		}).Error
	}
	if err != nil {
		return err
	}

	existing.Certificate = certPEM
	existing.PrivateKey = keyPEM
	existing.NotBefore = notBefore
	existing.NotAfter = notAfter
	return s.db.WithContext(ctx).Save(&existing).Error
}

func (s *DBCertificateStore) StorePEM(ctx context.Context, domainName, issuerKey string, certPEM, keyPEM []byte, metadata []byte) error {
	storedKey := append([]byte(nil), keyPEM...)
	if len(s.dataSecrets) > 0 && !secureconfig.IsEncryptedBytes(storedKey) {
		encryptedKey, encryptErr := secureconfig.EncryptBytesV2(s.dataSecrets[0], storedKey)
		if encryptErr != nil {
			return encryptErr
		}
		storedKey = encryptedKey
	}

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	if len(pair.Certificate) == 0 {
		return errors.New("empty certificate chain")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}

	record := domain.StoredTLSCertificate{
		Domain:       normalizeDomain(domainName),
		IssuerKey:    issuerKey,
		Certificate:  certPEM,
		PrivateKey:   storedKey,
		MetadataJSON: string(metadata),
		NotBefore:    leaf.NotBefore.UTC(),
		NotAfter:     leaf.NotAfter.UTC(),
	}

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("domain = ?", record.Domain).Delete(&domain.StoredTLSCertificate{}).Error; err != nil {
			return err
		}
		return tx.Create(&record).Error
	})
}

func (s *DBCertificateStore) ListExpiringCertificates(ctx context.Context, within time.Duration) ([]CertificateMeta, error) {
	if within <= 0 {
		within = 30 * 24 * time.Hour
	}
	var rows []domain.StoredTLSCertificate
	if err := s.db.WithContext(ctx).
		Where("not_after <= ?", time.Now().UTC().Add(within)).
		Order("not_after asc").
		Find(&rows).Error; err != nil {
		return nil, err
	}

	out := make([]CertificateMeta, 0, len(rows))
	for _, row := range rows {
		out = append(out, CertificateMeta{
			Domain:    row.Domain,
			IssuerKey: row.IssuerKey,
			NotBefore: row.NotBefore,
			NotAfter:  row.NotAfter,
			UpdatedAt: row.UpdatedAt,
		})
	}
	return out, nil
}

func (s *DBCertificateStore) MigrateStoredPrivateKeys(ctx context.Context) (int, error) {
	if len(s.dataSecrets) == 0 {
		return 0, nil
	}
	var rows []domain.StoredTLSCertificate
	if err := s.db.WithContext(ctx).Find(&rows).Error; err != nil {
		return 0, err
	}
	updated := 0
	for _, row := range rows {
		if secureconfig.IsEncryptedBytes(row.PrivateKey) || len(row.PrivateKey) == 0 {
			continue
		}
		encrypted, err := secureconfig.EncryptBytesV2(s.dataSecrets[0], row.PrivateKey)
		if err != nil {
			return updated, err
		}
		if err := s.db.WithContext(ctx).Model(&domain.StoredTLSCertificate{}).Where("id = ?", row.ID).Update("private_key", encrypted).Error; err != nil {
			return updated, err
		}
		updated++
	}
	return updated, nil
}

func marshalCertificate(cert *tls.Certificate) ([]byte, []byte, time.Time, time.Time, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, nil, time.Time{}, time.Time{}, errors.New("certificate is empty")
	}

	certPEM := make([]byte, 0, len(cert.Certificate)*1024)
	for _, der := range cert.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	leaf := cert.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, nil, time.Time{}, time.Time{}, err
		}
	}

	return certPEM, keyPEM, leaf.NotBefore.UTC(), leaf.NotAfter.UTC(), nil
}

func normalizeDomain(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
