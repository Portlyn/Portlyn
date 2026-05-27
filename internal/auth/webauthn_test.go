package auth

import (
	"context"
	"sync"
	"testing"

	"portlyn/internal/domain"
)

type stubCredentialStore struct {
	mu    sync.Mutex
	items []domain.UserCredential
}

func (s *stubCredentialStore) ListByUser(ctx context.Context, userID uint) ([]domain.UserCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []domain.UserCredential{}
	for _, c := range s.items {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	return out, nil
}
func (s *stubCredentialStore) GetByCredentialID(ctx context.Context, id string) (*domain.UserCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.items {
		if c.CredentialID == id {
			c2 := c
			return &c2, nil
		}
	}
	return nil, nil
}
func (s *stubCredentialStore) Create(ctx context.Context, item *domain.UserCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	item.ID = uint(len(s.items) + 1)
	s.items = append(s.items, *item)
	return nil
}
func (s *stubCredentialStore) Update(ctx context.Context, item *domain.UserCredential) error {
	return nil
}
func (s *stubCredentialStore) Delete(ctx context.Context, userID, id uint) error {
	return nil
}

type stubUserReader struct{ user *domain.User }

func (s *stubUserReader) GetByID(ctx context.Context, id uint) (*domain.User, error) {
	return s.user, nil
}

func TestWebAuthnBeginRegistrationCreatesSession(t *testing.T) {
	svc := NewWebAuthnService(&stubCredentialStore{}, &stubUserReader{user: &domain.User{ID: 1, Email: "u@example.test"}})
	svc.Configure("Portlyn", "https://portlyn.example")
	result, err := svc.BeginRegistration(context.Background(), 1)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if result.SessionID == "" {
		t.Fatal("expected session id")
	}
	if result.Options == nil {
		t.Fatal("expected challenge options")
	}
	svc.sessionMu.Lock()
	if _, ok := svc.sessions[result.SessionID]; !ok {
		t.Fatal("session not stored")
	}
	svc.sessionMu.Unlock()
}

func TestWebAuthnConfigureRequiresFrontendURL(t *testing.T) {
	svc := NewWebAuthnService(&stubCredentialStore{}, &stubUserReader{user: &domain.User{ID: 1, Email: "u@example.test"}})
	_, err := svc.BeginRegistration(context.Background(), 1)
	if err == nil {
		t.Fatal("expected error without frontend base")
	}
}
