package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"

	"portlyn/internal/domain"
)

const mfaLoginScope = "mfa_login"

type MFAStatus struct {
	Enabled            bool   `json:"enabled"`
	PendingSetup       bool   `json:"pending_setup"`
	RecoveryCodeCount  int    `json:"recovery_code_count"`
	Issuer             string `json:"issuer"`
	RequireForAdmins   bool   `json:"require_for_admins"`
	RequiredForCurrent bool   `json:"required_for_current_user"`
}

type MFASetup struct {
	Secret        string   `json:"secret"`
	OtpAuthURL    string   `json:"otpauth_url"`
	RecoveryCodes []string `json:"recovery_codes"`
}

func (s *Service) MFAStatusForUser(ctx context.Context, userID uint) (*MFAStatus, error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	settings, _ := s.settings.Get(ctx)
	requireForAdmins := settings != nil && settings.RequireMFAForAdmins
	return &MFAStatus{
		Enabled:            user.MFAEnabled,
		PendingSetup:       strings.TrimSpace(user.MFAPendingSecret) != "",
		RecoveryCodeCount:  len(user.MFARecoveryCodes),
		Issuer:             s.issuer,
		RequireForAdmins:   requireForAdmins,
		RequiredForCurrent: requireForAdmins && user.Role == domain.RoleAdmin,
	}, nil
}

func (s *Service) BeginTOTPSetup(ctx context.Context, userID uint) (*MFASetup, error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	secret, err := randomBase32Secret(20)
	if err != nil {
		return nil, err
	}
	recoveryCodes, recoveryHashes, err := s.generateRecoveryCodes()
	if err != nil {
		return nil, err
	}
	encryptedSecret, err := s.encryptSecret(secret)
	if err != nil {
		return nil, err
	}
	user.MFAPendingSecret = encryptedSecret
	user.MFAPendingRecoveryCodes = domain.JSONStringSlice(recoveryHashes)
	if err := s.users.Update(ctx, user); err != nil {
		return nil, err
	}
	return &MFASetup{
		Secret:        secret,
		OtpAuthURL:    buildOTPAuthURL(s.issuer, user.Email, secret),
		RecoveryCodes: recoveryCodes,
	}, nil
}

func (s *Service) EnableTOTP(ctx context.Context, userID uint, code string) (*MFAStatus, error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	secret, err := s.decryptSecret(user.MFAPendingSecret)
	if err != nil || secret == "" {
		return nil, ErrInvalidToken
	}
	if !validateTOTP(secret, code, time.Now().UTC()) {
		return nil, ErrMFACodeInvalid
	}
	user.MFAEnabled = true
	user.MFASecret = user.MFAPendingSecret
	user.MFAPendingSecret = ""
	user.MFARecoveryCodes = append(domain.JSONStringSlice{}, user.MFAPendingRecoveryCodes...)
	user.MFAPendingRecoveryCodes = domain.JSONStringSlice{}
	if err := s.users.Update(ctx, user); err != nil {
		return nil, err
	}
	s.InvalidateUser(user.ID)
	return s.MFAStatusForUser(ctx, userID)
}

func (s *Service) DisableMFA(ctx context.Context, userID uint, code string) (*MFAStatus, error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !user.MFAEnabled {
		return s.MFAStatusForUser(ctx, userID)
	}
	ok, remaining, err := s.verifyMFAFactor(user, code)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrMFACodeInvalid
	}
	user.MFAEnabled = false
	user.MFASecret = ""
	user.MFAPendingSecret = ""
	user.MFARecoveryCodes = remaining
	user.MFAPendingRecoveryCodes = domain.JSONStringSlice{}
	if err := s.users.Update(ctx, user); err != nil {
		return nil, err
	}
	s.InvalidateUser(user.ID)
	return s.MFAStatusForUser(ctx, userID)
}

func (s *Service) RegenerateRecoveryCodes(ctx context.Context, userID uint, code string) ([]string, error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	ok, _, err := s.verifyMFAFactor(user, code)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrMFACodeInvalid
	}
	recoveryCodes, recoveryHashes, err := s.generateRecoveryCodes()
	if err != nil {
		return nil, err
	}
	user.MFARecoveryCodes = domain.JSONStringSlice(recoveryHashes)
	if err := s.users.Update(ctx, user); err != nil {
		return nil, err
	}
	return recoveryCodes, nil
}

func (s *Service) ResetUserMFA(ctx context.Context, userID uint) error {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	user.MFAEnabled = false
	user.MFASecret = ""
	user.MFAPendingSecret = ""
	user.MFARecoveryCodes = domain.JSONStringSlice{}
	user.MFAPendingRecoveryCodes = domain.JSONStringSlice{}
	if err := s.users.Update(ctx, user); err != nil {
		return err
	}
	s.InvalidateUser(user.ID)
	return s.RevokeAllUserSessions(ctx, user.ID)
}

func (s *Service) beginMFAChallenge(ctx context.Context, user *domain.User, meta RequestMetadata) (*LoginResult, error) {
	if !user.MFAEnabled {
		return nil, ErrMFASetupRequired
	}
	challengeToken, err := randomCode(18)
	if err != nil {
		return nil, err
	}
	item := &domain.LoginToken{
		UserID:     &user.ID,
		Email:      user.Email,
		Token:      hashToken(challengeToken),
		Scope:      mfaLoginScope,
		ExpiresAt:  time.Now().UTC().Add(10 * time.Minute),
		RemoteAddr: meta.RemoteAddr,
		UserAgent:  meta.UserAgent,
	}
	if err := s.loginTokens.Create(ctx, item); err != nil {
		return nil, err
	}
	return &LoginResult{
		User:         user,
		MFARequired:  true,
		MFAToken:     challengeToken,
		MFAExpiresAt: item.ExpiresAt,
	}, nil
}

func (s *Service) CompleteMFA(ctx context.Context, mfaToken, code string, meta RequestMetadata) (*LoginResult, error) {
	item, err := s.loginTokens.GetValidTokenByScope(ctx, "", mfaToken, mfaLoginScope, nil)
	if err != nil {
		return nil, ErrInvalidToken
	}
	if item.UsedAt != nil {
		return nil, ErrInvalidToken
	}
	if item.ExpiresAt.Before(time.Now().UTC()) || item.UserID == nil {
		return nil, ErrInvalidToken
	}
	user, err := s.users.GetByID(ctx, *item.UserID)
	if err != nil {
		return nil, err
	}
	ok, remaining, err := s.verifyMFAFactor(user, code)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrMFACodeInvalid
	}
	if err := s.loginTokens.MarkUsed(ctx, item.ID, time.Now().UTC()); err != nil {
		return nil, err
	}
	if len(remaining) != len(user.MFARecoveryCodes) {
		user.MFARecoveryCodes = remaining
		if err := s.users.Update(ctx, user); err != nil {
			return nil, err
		}
	}
	return s.completeSuccessfulLogin(ctx, user, meta)
}

func (s *Service) verifyMFAFactor(user *domain.User, code string) (bool, domain.JSONStringSlice, error) {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return false, user.MFARecoveryCodes, nil
	}
	if secret, err := s.decryptSecret(user.MFASecret); err == nil && secret != "" && validateTOTP(secret, code, time.Now().UTC()) {
		return true, user.MFARecoveryCodes, nil
	}
	remaining := make(domain.JSONStringSlice, 0, len(user.MFARecoveryCodes))
	matched := false
	for _, item := range user.MFARecoveryCodes {
		if !matched && subtleEqualHash(item, hashToken(code)) {
			matched = true
			continue
		}
		remaining = append(remaining, item)
	}
	return matched, remaining, nil
}

func (s *Service) shouldRequireMFA(ctx context.Context, user *domain.User) bool {
	if user == nil {
		return false
	}
	if user.MFAEnabled {
		return true
	}
	settings, _ := s.settings.Get(ctx)
	if settings == nil || !settings.RequireMFAForAdmins || user.Role != domain.RoleAdmin {
		return false
	}
	return !s.userHasPasskey(ctx, user.ID)
}

func (s *Service) enforceAdminMFARequirement(ctx context.Context, user *domain.User) error {
	if user == nil || user.MFAEnabled || user.Role != domain.RoleAdmin {
		return nil
	}
	settings, _ := s.settings.Get(ctx)
	if settings != nil && settings.RequireMFAForAdmins && !s.userHasPasskey(ctx, user.ID) {
		return ErrMFASetupRequired
	}
	return nil
}

func (s *Service) generateRecoveryCodes() ([]string, []string, error) {
	plain := make([]string, 0, 8)
	hashed := make([]string, 0, 8)
	for range 8 {
		value, err := randomCode(5)
		if err != nil {
			return nil, nil, err
		}
		code := value[:5] + "-" + value[5:10]
		plain = append(plain, code)
		hashed = append(hashed, hashToken(code))
	}
	return plain, hashed, nil
}

func randomBase32Secret(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return strings.TrimRight(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), "="), nil
}

func buildOTPAuthURL(issuer, email, secret string) string {
	label := url.PathEscape(strings.TrimSpace(issuer) + ":" + strings.ToLower(strings.TrimSpace(email)))
	values := url.Values{}
	values.Set("secret", secret)
	values.Set("issuer", strings.TrimSpace(issuer))
	values.Set("algorithm", "SHA1")
	values.Set("digits", "6")
	values.Set("period", "30")
	return "otpauth://totp/" + label + "?" + values.Encode()
}

func validateTOTP(secret, code string, now time.Time) bool {
	for _, offset := range []int64{-30, 0, 30} {
		if generateTOTP(secret, now.Add(time.Duration(offset)*time.Second)) == code {
			return true
		}
	}
	return false
}

func generateTOTP(secret string, now time.Time) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return ""
	}
	counter := uint64(now.Unix() / 30)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0F
	code := (int(sum[offset])&0x7F)<<24 | int(sum[offset+1])<<16 | int(sum[offset+2])<<8 | int(sum[offset+3])
	return fmt.Sprintf("%06d", code%1_000_000)
}

func (s *Service) encryptSecret(value string) (string, error) {
	block, err := aes.NewCipher(deriveSecretKey(s.mfaEncryptionSecret))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(value), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (s *Service) decryptSecret(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(deriveSecretKey(s.mfaEncryptionSecret))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", ErrInvalidToken
	}
	nonce := raw[:gcm.NonceSize()]
	plaintext, err := gcm.Open(nil, nonce, raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func deriveSecretKey(source []byte) []byte {
	sum := sha256.Sum256(source)
	return sum[:]
}

func subtleEqualHash(left, right string) bool {
	return hmac.Equal([]byte(strings.TrimSpace(left)), []byte(strings.TrimSpace(right)))
}
