package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"portlyn/internal/domain"
	"portlyn/internal/store"
)

type WebAuthnSessionStore interface {
	Save(ctx context.Context, id string, entry webauthnSessionEntry, ttl time.Duration) error
	Pop(ctx context.Context, id string) (webauthnSessionEntry, bool)
}

type CredentialStore interface {
	ListByUser(ctx context.Context, userID uint) ([]domain.UserCredential, error)
	GetByCredentialID(ctx context.Context, credentialID string) (*domain.UserCredential, error)
	Create(ctx context.Context, item *domain.UserCredential) error
	Update(ctx context.Context, item *domain.UserCredential) error
	Delete(ctx context.Context, userID, id uint) error
}

type WebAuthnService struct {
	credentials CredentialStore
	users       UserStoreReader
	sessionMu   sync.Mutex
	sessions    map[string]webauthnSessionEntry
	store       WebAuthnSessionStore

	rpDisplayName string
	frontendBase  string
}

type webauthnSessionEntry struct {
	UserID  uint
	Session webauthn.SessionData
	Purpose string
	Expires time.Time
}

type UserStoreReader interface {
	GetByID(ctx context.Context, id uint) (*domain.User, error)
}

func NewWebAuthnService(credentials CredentialStore, users UserStoreReader) *WebAuthnService {
	return &WebAuthnService{
		credentials: credentials,
		users:       users,
		sessions:    map[string]webauthnSessionEntry{},
	}
}

func (w *WebAuthnService) Configure(rpDisplayName, frontendBase string) {
	w.rpDisplayName = strings.TrimSpace(rpDisplayName)
	w.frontendBase = strings.TrimRight(strings.TrimSpace(frontendBase), "/")
}

func (w *WebAuthnService) SetSessionStore(store WebAuthnSessionStore) {
	w.store = store
}

func (w *WebAuthnService) instance() (*webauthn.WebAuthn, error) {
	if w.frontendBase == "" {
		return nil, errors.New("webauthn: frontend base url not configured")
	}
	parsed, err := url.Parse(w.frontendBase)
	if err != nil {
		return nil, fmt.Errorf("webauthn: parse frontend base url: %w", err)
	}
	rpID := parsed.Hostname()
	if rpID == "" {
		return nil, errors.New("webauthn: frontend base url has no host")
	}
	cfg := &webauthn.Config{
		RPID:          rpID,
		RPDisplayName: firstNonEmptyAuth(w.rpDisplayName, "Portlyn"),
		RPOrigins:     []string{w.frontendBase},
	}
	return webauthn.New(cfg)
}

type webauthnUser struct {
	user        *domain.User
	credentials []domain.UserCredential
}

func (u *webauthnUser) WebAuthnID() []byte {
	return []byte(fmt.Sprintf("user-%d", u.user.ID))
}
func (u *webauthnUser) WebAuthnName() string { return u.user.Email }
func (u *webauthnUser) WebAuthnDisplayName() string {
	if u.user.DisplayName != "" {
		return u.user.DisplayName
	}
	return u.user.Email
}
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(u.credentials))
	for _, c := range u.credentials {
		credID, _ := base64.RawURLEncoding.DecodeString(c.CredentialID)
		pubKey, _ := base64.StdEncoding.DecodeString(c.PublicKey)
		out = append(out, webauthn.Credential{
			ID:        credID,
			PublicKey: pubKey,
			Authenticator: webauthn.Authenticator{
				SignCount: c.SignCount,
			},
		})
	}
	return out
}

type BeginRegistrationResult struct {
	Options   *protocol.CredentialCreation `json:"options"`
	SessionID string                       `json:"session_id"`
	ExpiresAt time.Time                    `json:"expires_at"`
}

func (w *WebAuthnService) BeginRegistration(ctx context.Context, userID uint) (*BeginRegistrationResult, error) {
	instance, err := w.instance()
	if err != nil {
		return nil, err
	}
	user, err := w.users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	creds, err := w.credentials.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	wu := &webauthnUser{user: user, credentials: creds}
	options, session, err := instance.BeginRegistration(wu)
	if err != nil {
		return nil, err
	}
	id, err := randomSessionID()
	if err != nil {
		return nil, err
	}
	w.storeSession(id, webauthnSessionEntry{UserID: userID, Session: *session, Purpose: "register"})
	return &BeginRegistrationResult{Options: options, SessionID: id, ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
}

func (w *WebAuthnService) FinishRegistration(ctx context.Context, sessionID, label string, response *http.Request) (*domain.UserCredential, error) {
	entry, ok := w.popSession(sessionID, "register")
	if !ok {
		return nil, errors.New("webauthn: unknown or expired session")
	}
	instance, err := w.instance()
	if err != nil {
		return nil, err
	}
	user, err := w.users.GetByID(ctx, entry.UserID)
	if err != nil {
		return nil, err
	}
	creds, err := w.credentials.ListByUser(ctx, entry.UserID)
	if err != nil {
		return nil, err
	}
	wu := &webauthnUser{user: user, credentials: creds}
	credential, err := instance.FinishRegistration(wu, entry.Session, response)
	if err != nil {
		return nil, err
	}
	item := &domain.UserCredential{
		UserID:          entry.UserID,
		CredentialID:    base64.RawURLEncoding.EncodeToString(credential.ID),
		PublicKey:       base64.StdEncoding.EncodeToString(credential.PublicKey),
		AttestationType: credential.AttestationType,
		AAGUID:          base64.RawURLEncoding.EncodeToString(credential.Authenticator.AAGUID),
		SignCount:       credential.Authenticator.SignCount,
		Label:           strings.TrimSpace(label),
		UserVerified:    credential.Flags.UserVerified,
	}
	if err := w.credentials.Create(ctx, item); err != nil {
		return nil, err
	}
	return item, nil
}

type BeginLoginResult struct {
	Options   *protocol.CredentialAssertion `json:"options"`
	SessionID string                        `json:"session_id"`
	ExpiresAt time.Time                     `json:"expires_at"`
}

func (w *WebAuthnService) BeginLogin(ctx context.Context, userID uint) (*BeginLoginResult, error) {
	instance, err := w.instance()
	if err != nil {
		return nil, err
	}
	user, err := w.users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	creds, err := w.credentials.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return nil, errors.New("no credentials registered")
	}
	wu := &webauthnUser{user: user, credentials: creds}
	options, session, err := instance.BeginLogin(wu)
	if err != nil {
		return nil, err
	}
	id, err := randomSessionID()
	if err != nil {
		return nil, err
	}
	w.storeSession(id, webauthnSessionEntry{UserID: userID, Session: *session, Purpose: "login"})
	return &BeginLoginResult{Options: options, SessionID: id, ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
}

func (w *WebAuthnService) FinishLogin(ctx context.Context, sessionID string, response *http.Request) error {
	entry, ok := w.popSession(sessionID, "login")
	if !ok {
		return errors.New("webauthn: unknown or expired session")
	}
	instance, err := w.instance()
	if err != nil {
		return err
	}
	user, err := w.users.GetByID(ctx, entry.UserID)
	if err != nil {
		return err
	}
	creds, err := w.credentials.ListByUser(ctx, entry.UserID)
	if err != nil {
		return err
	}
	wu := &webauthnUser{user: user, credentials: creds}
	credential, err := instance.FinishLogin(wu, entry.Session, response)
	if err != nil {
		return err
	}
	stored, err := w.credentials.GetByCredentialID(ctx, base64.RawURLEncoding.EncodeToString(credential.ID))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return errors.New("credential not found")
		}
		return err
	}
	now := time.Now().UTC()
	stored.SignCount = credential.Authenticator.SignCount
	stored.LastUsedAt = &now
	return w.credentials.Update(ctx, stored)
}

func (w *WebAuthnService) ListCredentials(ctx context.Context, userID uint) ([]domain.UserCredential, error) {
	return w.credentials.ListByUser(ctx, userID)
}

func (w *WebAuthnService) DeleteCredential(ctx context.Context, userID, id uint) error {
	return w.credentials.Delete(ctx, userID, id)
}

func (w *WebAuthnService) storeSession(id string, entry webauthnSessionEntry) {
	ttl := 5 * time.Minute
	entry.Expires = time.Now().Add(ttl)
	if w.store != nil {
		if err := w.store.Save(context.Background(), id, entry, ttl); err == nil {
			return
		}
	}
	w.sessionMu.Lock()
	defer w.sessionMu.Unlock()
	w.sessions[id] = entry
	for key, val := range w.sessions {
		if time.Now().After(val.Expires) {
			delete(w.sessions, key)
		}
	}
}

func (w *WebAuthnService) popSession(id, purpose string) (webauthnSessionEntry, bool) {
	if w.store != nil {
		entry, ok := w.store.Pop(context.Background(), id)
		if ok {
			if entry.Purpose != purpose || time.Now().After(entry.Expires) {
				return webauthnSessionEntry{}, false
			}
			return entry, true
		}
	}
	w.sessionMu.Lock()
	defer w.sessionMu.Unlock()
	entry, ok := w.sessions[id]
	if !ok {
		return webauthnSessionEntry{}, false
	}
	delete(w.sessions, id)
	if entry.Purpose != purpose || time.Now().After(entry.Expires) {
		return webauthnSessionEntry{}, false
	}
	return entry, true
}

func randomSessionID() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func firstNonEmptyAuth(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func ParseClientResponseRequest(body string) (*http.Request, error) {
	if !json.Valid([]byte(body)) {
		return nil, errors.New("invalid json")
	}
	r, err := http.NewRequest(http.MethodPost, "http://localhost/", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	return r, nil
}
