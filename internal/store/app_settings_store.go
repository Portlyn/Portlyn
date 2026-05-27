package store

import (
	"context"
	"errors"
	"strings"

	"gorm.io/gorm"

	"portlyn/internal/config"
	"portlyn/internal/domain"
	"portlyn/internal/secureconfig"
)

const appSettingsSingletonID uint = 1

type AppSettingsStore struct {
	db                  *gorm.DB
	dataEncryptionBytes [][]byte
}

func NewAppSettingsStore(db *gorm.DB) *AppSettingsStore {
	return &AppSettingsStore{db: db}
}

func (s *AppSettingsStore) SetDataEncryptionSecrets(values []string) {
	out := make([][]byte, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		out = append(out, []byte(trimmed))
	}
	s.dataEncryptionBytes = out
}

func (s *AppSettingsStore) Get(ctx context.Context) (*domain.AppSettings, error) {
	var item domain.AppSettings
	err := s.db.WithContext(ctx).First(&item, appSettingsSingletonID).Error
	if err == nil {
		if decryptErr := s.decryptSecretFields(&item); decryptErr != nil {
			return nil, decryptErr
		}
		return &item, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, err
}

func (s *AppSettingsStore) Upsert(ctx context.Context, item *domain.AppSettings) error {
	item.ID = appSettingsSingletonID
	encrypted := *item
	if err := s.encryptSecretFields(&encrypted); err != nil {
		return err
	}
	return s.db.WithContext(ctx).Save(&encrypted).Error
}

func (s *AppSettingsStore) SeedDefaults(ctx context.Context, cfg config.Config) error {
	s.SetDataEncryptionSecrets(cfg.DataEncryptionSecrets())
	_, err := s.Get(ctx)
	if err == nil {
		return nil
	}
	if err != ErrNotFound {
		return err
	}

	item := &domain.AppSettings{
		ID:                        appSettingsSingletonID,
		FrontendBaseURL:           cfg.FrontendBaseURL,
		AuthBrandName:             "Portlyn",
		AuthBackgroundColor:       "#0a0d14",
		AuthBackgroundAccent:      "#162033",
		AuthPanelColor:            "#111826",
		AuthButtonColor:           "#2f6fed",
		AuthTextColor:             "#f8fafc",
		AuthMutedTextColor:        "#94a3b8",
		AuthLoginTitle:            "Login",
		AuthRouteLoginTitle:       "Login",
		AuthForbiddenTitle:        "Access denied",
		AuthLoginPasswordLabel:    "Login",
		AuthLoginOIDCLabel:        "Continue with SSO",
		AuthLoginOTPRequestLabel:  "Request code",
		AuthLoginOTPVerifyLabel:   "Verify code",
		AuthRouteContinueLabel:    "Continue",
		AuthRouteOIDCLabel:        "Continue with SSO",
		AuthRoutePINLabel:         "Unlock",
		AuthRouteEmailSendLabel:   "Send code",
		AuthRouteEmailVerifyLabel: "Verify code",
		AuthForbiddenRetryLabel:   "Try again",
		OIDCEnabled:               cfg.OIDC.Enabled,
		OIDCIssuerURL:             cfg.OIDC.IssuerURL,
		OIDCClientID:              cfg.OIDC.ClientID,
		OIDCClientSecret:          cfg.OIDC.ClientSecret,
		OIDCRedirectURL:           cfg.OIDC.RedirectURL,
		OIDCAllowedEmailDomains:   domain.JSONStringSlice(cfg.OIDC.AllowedEmailDomains),
		OIDCAdminRoleClaimPath:    cfg.OIDC.AdminRoleClaimPath,
		OIDCAdminRoleValue:        cfg.OIDC.AdminRoleValue,
		OIDCProviderLabel:         cfg.OIDC.DefaultProviderLabel,
		OIDCAllowEmailLinking:     cfg.OIDC.AllowEmailLinking,
		OIDCRequireVerifiedEmail:  cfg.OIDC.RequireVerifiedEmail,
		OTPEnabled:                cfg.OTP.Enabled,
		OTPTokenTTLSeconds:        int(cfg.OTP.TokenTTL.Seconds()),
		OTPRequestLimit:           cfg.OTP.RequestLimit,
		OTPRequestWindowSeconds:   int(cfg.OTP.RequestWindow.Seconds()),
		RequireMFAForAdmins:       cfg.RequireMFAForAdmins,
		SMTPPort:                  587,
		SMTPEncryption:            "starttls",
	}
	return s.Upsert(ctx, item)
}

func (s *AppSettingsStore) MigrateStoredSecrets(ctx context.Context) (int, error) {
	if len(s.dataEncryptionBytes) == 0 {
		return 0, nil
	}
	var item domain.AppSettings
	err := s.db.WithContext(ctx).First(&item, appSettingsSingletonID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}

	updated := 0
	if strings.TrimSpace(item.OIDCClientSecret) != "" && !secureconfig.IsEncryptedValue(item.OIDCClientSecret) {
		encrypted, encryptErr := secureconfig.EncryptStringV2(s.dataEncryptionBytes[0], item.OIDCClientSecret)
		if encryptErr != nil {
			return updated, encryptErr
		}
		item.OIDCClientSecret = encrypted
		updated++
	}
	if strings.TrimSpace(item.SMTPPassword) != "" && !secureconfig.IsEncryptedValue(item.SMTPPassword) {
		encrypted, encryptErr := secureconfig.EncryptStringV2(s.dataEncryptionBytes[0], item.SMTPPassword)
		if encryptErr != nil {
			return updated, encryptErr
		}
		item.SMTPPassword = encrypted
		updated++
	}
	if updated == 0 {
		return 0, nil
	}
	return updated, s.db.WithContext(ctx).Save(&item).Error
}

func (s *AppSettingsStore) encryptSecretFields(item *domain.AppSettings) error {
	if item == nil {
		return nil
	}
	if len(s.dataEncryptionBytes) == 0 {
		return nil
	}
	if strings.TrimSpace(item.OIDCClientSecret) != "" && !secureconfig.IsEncryptedValue(item.OIDCClientSecret) {
		encrypted, err := secureconfig.EncryptStringV2(s.dataEncryptionBytes[0], item.OIDCClientSecret)
		if err != nil {
			return err
		}
		item.OIDCClientSecret = encrypted
	}
	if strings.TrimSpace(item.SMTPPassword) != "" && !secureconfig.IsEncryptedValue(item.SMTPPassword) {
		encrypted, err := secureconfig.EncryptStringV2(s.dataEncryptionBytes[0], item.SMTPPassword)
		if err != nil {
			return err
		}
		item.SMTPPassword = encrypted
	}
	if strings.TrimSpace(item.TunnelServerPrivateKey) != "" && !secureconfig.IsEncryptedValue(item.TunnelServerPrivateKey) {
		encrypted, err := secureconfig.EncryptStringV2(s.dataEncryptionBytes[0], item.TunnelServerPrivateKey)
		if err != nil {
			return err
		}
		item.TunnelServerPrivateKey = encrypted
	}
	if strings.TrimSpace(item.CrowdSecAPIKeyEncrypted) != "" && !secureconfig.IsEncryptedValue(item.CrowdSecAPIKeyEncrypted) {
		encrypted, err := secureconfig.EncryptStringV2(s.dataEncryptionBytes[0], item.CrowdSecAPIKeyEncrypted)
		if err != nil {
			return err
		}
		item.CrowdSecAPIKeyEncrypted = encrypted
	}
	return nil
}

func (s *AppSettingsStore) decryptSecretFields(item *domain.AppSettings) error {
	if item == nil {
		return nil
	}
	if strings.TrimSpace(item.OIDCClientSecret) != "" && secureconfig.IsEncryptedValue(item.OIDCClientSecret) {
		plaintext, err := secureconfig.DecryptStringAuto(s.dataEncryptionBytes, item.OIDCClientSecret)
		if err != nil {
			return err
		}
		item.OIDCClientSecret = plaintext
	}
	if strings.TrimSpace(item.SMTPPassword) != "" && secureconfig.IsEncryptedValue(item.SMTPPassword) {
		plaintext, err := secureconfig.DecryptStringAuto(s.dataEncryptionBytes, item.SMTPPassword)
		if err != nil {
			return err
		}
		item.SMTPPassword = plaintext
	}
	if strings.TrimSpace(item.TunnelServerPrivateKey) != "" && secureconfig.IsEncryptedValue(item.TunnelServerPrivateKey) {
		plaintext, err := secureconfig.DecryptStringAuto(s.dataEncryptionBytes, item.TunnelServerPrivateKey)
		if err != nil {
			return err
		}
		item.TunnelServerPrivateKey = plaintext
	}
	if strings.TrimSpace(item.CrowdSecAPIKeyEncrypted) != "" && secureconfig.IsEncryptedValue(item.CrowdSecAPIKeyEncrypted) {
		plaintext, err := secureconfig.DecryptStringAuto(s.dataEncryptionBytes, item.CrowdSecAPIKeyEncrypted)
		if err != nil {
			return err
		}
		item.CrowdSecAPIKeyEncrypted = plaintext
	}
	return nil
}
