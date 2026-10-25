package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"portlyn/internal/domain"
)

func invalidUTF8AuditLog() domain.AuditLog {
	return domain.AuditLog{
		Timestamp:    time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
		Action:       "proxy_access",
		ResourceType: "service",
		Method:       "GET",
		Host:         "app.example.com",
		Path:         "/a\xffb",
		StatusCode:   403,
		UserAgent:    "curl\xff\xfe",
	}
}

func TestAuditHashPayloadEncodesInvalidUTF8Explicitly(t *testing.T) {
	item := invalidUTF8AuditLog()

	current, _ := json.Marshal(auditHashPayload("", &item, string(utf8.RuneError)))
	if !strings.Contains(string(current), `"user_agent":"curl`+strings.Repeat(string(utf8.RuneError), 2)+`"`) {
		t.Fatalf("current payload: %s", current)
	}

	legacy, _ := json.Marshal(auditHashPayload("", &item, legacyInvalidUTF8Marker))
	legacy = []byte(strings.ReplaceAll(string(legacy), legacyInvalidUTF8Marker, legacyInvalidUTF8Escape))
	if !strings.Contains(string(legacy), `"user_agent":"curl`+strings.Repeat(legacyInvalidUTF8Escape, 2)+`"`) || !strings.Contains(string(legacy), `"path":"/a`+legacyInvalidUTF8Escape+`b"`) {
		t.Fatalf("legacy payload: %s", legacy)
	}
}

func TestVerifyAcceptsRowsHashedByEitherJSONEncoder(t *testing.T) {
	key := []byte("test-key")
	legacy := invalidUTF8AuditLog()
	legacy.ID = 1
	legacy.Hash = computeLegacyAuditHash(key, "", &legacy)

	current := invalidUTF8AuditLog()
	current.ID = 2
	current.PrevHash = legacy.Hash
	current.Hash = computeAuditHash(key, legacy.Hash, &current)

	if legacy.Hash == computeAuditHash(key, "", &legacy) {
		t.Fatal("expected legacy and current hashes to differ for invalid utf-8")
	}
	if err := VerifyAuditHashChain(key, []domain.AuditLog{legacy, current}); err != nil {
		t.Fatalf("verify: %v", err)
	}

	tampered := legacy
	tampered.UserAgent = "wget\xff\xfe"
	if err := VerifyAuditHashChain(key, []domain.AuditLog{tampered}); err == nil {
		t.Fatal("expected tampered row to fail verification")
	}
}

func TestAuditCreateStoresValidUTF8AndKeepsChainAfterLegacyRows(t *testing.T) {
	s := newAuditTestStore(t)
	ctx := context.Background()

	legacy := invalidUTF8AuditLog()
	legacy.Hash = computeLegacyAuditHash(s.hmacKey, "", &legacy)
	if err := s.db.WithContext(ctx).Create(&legacy).Error; err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	item := invalidUTF8AuditLog()
	if err := s.Create(ctx, &item); err != nil {
		t.Fatalf("create: %v", err)
	}
	var stored domain.AuditLog
	if err := s.db.WithContext(ctx).First(&stored, item.ID).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	if !utf8.ValidString(stored.UserAgent) || !utf8.ValidString(stored.Path) {
		t.Fatalf("stored invalid utf-8: %q %q", stored.UserAgent, stored.Path)
	}

	result, err := s.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if result.Verified != 2 {
		t.Fatalf("expected 2 verified rows, got %d", result.Verified)
	}
}
