package auth

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestLoginUnknownEmailRunsDummyBcrypt(t *testing.T) {
	service, _ := newStoreBackedService(t)
	if _, err := service.Login(context.Background(), "nobody@example.com", "whatever", RequestMetadata{RemoteAddr: "192.0.2.1:1234"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
	cost, err := bcrypt.Cost(dummyPasswordHash)
	if err != nil {
		t.Fatalf("dummy hash was not prepared: %v", err)
	}
	if cost != PasswordHashCost {
		t.Fatalf("expected dummy hash cost %d, got %d", PasswordHashCost, cost)
	}
}
