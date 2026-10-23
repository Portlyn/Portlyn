package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type InMemoryConfigCache struct {
	mu    sync.RWMutex
	items map[string]memoryCacheEntry
}

type memoryCacheEntry struct {
	routes    []RouteConfig
	expiresAt time.Time
}

func NewInMemoryConfigCache() *InMemoryConfigCache {
	return &InMemoryConfigCache{items: make(map[string]memoryCacheEntry)}
}

func (c *InMemoryConfigCache) GetRoutesForHost(_ context.Context, host string) ([]RouteConfig, bool, error) {
	host = normalizeHost(host)
	now := time.Now().UTC()

	c.mu.RLock()
	entry, ok := c.items[host]
	c.mu.RUnlock()
	if !ok {
		return nil, false, nil
	}
	if now.After(entry.expiresAt) {
		c.mu.Lock()
		delete(c.items, host)
		c.mu.Unlock()
		return nil, false, nil
	}
	return cloneRouteConfigs(entry.routes), true, nil
}

func (c *InMemoryConfigCache) SetRoutesForHost(_ context.Context, host string, routes []RouteConfig, ttl time.Duration) error {
	if ttl <= 0 {
		return c.InvalidateHost(context.Background(), host)
	}
	c.mu.Lock()
	c.items[normalizeHost(host)] = memoryCacheEntry{
		routes:    cloneRouteConfigs(routes),
		expiresAt: time.Now().UTC().Add(ttl),
	}
	c.mu.Unlock()
	return nil
}

func (c *InMemoryConfigCache) InvalidateHost(_ context.Context, host string) error {
	c.mu.Lock()
	delete(c.items, normalizeHost(host))
	c.mu.Unlock()
	return nil
}

func (c *InMemoryConfigCache) InvalidateAll(context.Context) error {
	c.mu.Lock()
	c.items = make(map[string]memoryCacheEntry)
	c.mu.Unlock()
	return nil
}

type RedisConfigCache struct {
	client *redis.Client
	prefix string
}

func NewRedisConfigCache(client *redis.Client, prefix string) *RedisConfigCache {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = "portlyn:routes"
	}
	return &RedisConfigCache{client: client, prefix: prefix}
}

func (c *RedisConfigCache) GetRoutesForHost(ctx context.Context, host string) ([]RouteConfig, bool, error) {
	value, err := c.client.Get(ctx, c.key(host)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, false, nil
		}
		return nil, false, err
	}

	var routes []RouteConfig
	if err := json.Unmarshal(value, &routes); err != nil {
		return nil, false, err
	}
	return routes, true, nil
}

func (c *RedisConfigCache) SetRoutesForHost(ctx context.Context, host string, routes []RouteConfig, ttl time.Duration) error {
	payload, err := json.Marshal(routes)
	if err != nil {
		return err
	}
	return c.client.Set(ctx, c.key(host), payload, ttl).Err()
}

func (c *RedisConfigCache) InvalidateHost(ctx context.Context, host string) error {
	return c.client.Del(ctx, c.key(host)).Err()
}

func (c *RedisConfigCache) InvalidateAll(ctx context.Context) error {
	iter := c.client.Scan(ctx, 0, c.prefix+":*", 500).Iterator()
	keys := make([]string, 0, 500)
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
		if len(keys) == cap(keys) {
			if err := c.client.Del(ctx, keys...).Err(); err != nil {
				return err
			}
			keys = keys[:0]
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	if len(keys) == 0 {
		return nil
	}
	return c.client.Del(ctx, keys...).Err()
}

func (c *RedisConfigCache) key(host string) string {
	return c.prefix + ":" + normalizeHost(host)
}

func cloneRouteConfigs(in []RouteConfig) []RouteConfig {
	out := make([]RouteConfig, len(in))
	copy(out, in)
	return out
}
