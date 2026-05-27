package auth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisWebAuthnSessionStore struct {
	client *redis.Client
	prefix string
}

func NewRedisWebAuthnSessionStore(client *redis.Client, prefix string) *RedisWebAuthnSessionStore {
	if prefix == "" {
		prefix = "portlyn:webauthn:session:"
	}
	return &RedisWebAuthnSessionStore{client: client, prefix: prefix}
}

type redisSessionPayload struct {
	UserID  uint   `json:"user_id"`
	Purpose string `json:"purpose"`
	Expires int64  `json:"expires"`
	Session []byte `json:"session"`
}

func (s *RedisWebAuthnSessionStore) Save(ctx context.Context, id string, entry webauthnSessionEntry, ttl time.Duration) error {
	if s.client == nil {
		return errors.New("redis client not configured")
	}
	sessionBlob, err := json.Marshal(entry.Session)
	if err != nil {
		return err
	}
	payload := redisSessionPayload{
		UserID:  entry.UserID,
		Purpose: entry.Purpose,
		Expires: entry.Expires.UnixNano(),
		Session: sessionBlob,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, s.prefix+id, encoded, ttl).Err()
}

func (s *RedisWebAuthnSessionStore) Pop(ctx context.Context, id string) (webauthnSessionEntry, bool) {
	if s.client == nil {
		return webauthnSessionEntry{}, false
	}
	key := s.prefix + id
	value, err := s.client.GetDel(ctx, key).Bytes()
	if err != nil || len(value) == 0 {
		return webauthnSessionEntry{}, false
	}
	var payload redisSessionPayload
	if err := json.Unmarshal(value, &payload); err != nil {
		return webauthnSessionEntry{}, false
	}
	entry := webauthnSessionEntry{
		UserID:  payload.UserID,
		Purpose: payload.Purpose,
		Expires: time.Unix(0, payload.Expires),
	}
	if err := json.Unmarshal(payload.Session, &entry.Session); err != nil {
		return webauthnSessionEntry{}, false
	}
	return entry, true
}
