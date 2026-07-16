package auth

import (
	"context"
	"testing"
	"time"

	"portlyn/internal/domain"
	"portlyn/internal/store"
)

type fakeAPITokenStore struct {
	rec     *domain.APIToken
	touched bool
}

func (f *fakeAPITokenStore) FindActiveByPrefix(_ context.Context, prefix string) (*domain.APIToken, error) {
	if f.rec != nil && f.rec.Prefix == prefix && f.rec.RevokedAt == nil {
		return f.rec, nil
	}
	return nil, store.ErrNotFound
}

func (f *fakeAPITokenStore) TouchLastUsed(_ context.Context, _ uint, _ time.Time) error {
	f.touched = true
	return nil
}

func TestGenerateAndAuthenticateAPIToken(t *testing.T) {
	prefix, token, hash, err := GenerateAPIToken()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !LooksLikeAPIToken(token) {
		t.Fatal("generated token should look like an api token")
	}
	if got, ok := apiTokenPrefix(token); !ok || got != prefix {
		t.Fatalf("prefix parse mismatch: got %q ok=%v want %q", got, ok, prefix)
	}
	if HashAPIToken(token) != hash {
		t.Fatal("hash mismatch for generated token")
	}

	fake := &fakeAPITokenStore{rec: &domain.APIToken{ID: 7, Name: "ci", Prefix: prefix, TokenHash: hash, Role: domain.RoleAdmin}}
	s := &Service{}
	s.SetAPITokenStore(fake)

	user, _, _, err := s.authenticateAPIToken(context.Background(), token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if user.Role != domain.RoleAdmin {
		t.Fatalf("expected admin role, got %q", user.Role)
	}
	if !fake.touched {
		t.Fatal("expected last-used to be touched")
	}

	if _, _, _, err := s.authenticateAPIToken(context.Background(), token+"tampered"); err == nil {
		t.Fatal("expected tampered token to fail")
	}

	expired := &fakeAPITokenStore{rec: &domain.APIToken{ID: 8, Prefix: prefix, TokenHash: hash, Role: domain.RoleViewer, ExpiresAt: ptrTime(time.Now().UTC().Add(-time.Hour))}}
	s.SetAPITokenStore(expired)
	if _, _, _, err := s.authenticateAPIToken(context.Background(), token); err == nil {
		t.Fatal("expected expired token to fail")
	}
}

func TestAPITokenPrefixHandlesUnderscoreSecret(t *testing.T) {
	prefix, ok := apiTokenPrefix("plyn_f5e69d01_ab_cd-ef_gh")
	if !ok || prefix != "plyn_f5e69d01" {
		t.Fatalf("expected prefix plyn_f5e69d01, got %q ok=%v", prefix, ok)
	}
	if _, ok := apiTokenPrefix("plyn_only"); ok {
		t.Fatal("token without a secret segment must not parse")
	}
	if _, ok := apiTokenPrefix("nope_ab_cd"); ok {
		t.Fatal("token with wrong scheme must not parse")
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
