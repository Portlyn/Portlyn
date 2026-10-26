package acme

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	"gorm.io/gorm"
)

const (
	certificateCacheFreshFor  = time.Minute
	certificateCacheMissFor   = 30 * time.Second
	certificateCacheLoadLimit = 10 * time.Second
	maxCachedCertificateMiss  = 4096
)

type cachedCertificate struct {
	cert     *tls.Certificate
	loadedAt time.Time
}

type certificateCache struct {
	mu     sync.RWMutex
	hits   map[string]cachedCertificate
	misses map[string]time.Time
	gen    uint64
	group  singleflight.Group
	now    func() time.Time
}

func newCertificateCache() *certificateCache {
	return &certificateCache{
		hits:   make(map[string]cachedCertificate),
		misses: make(map[string]time.Time),
		now:    time.Now,
	}
}

func (c *certificateCache) get(ctx context.Context, name string, load func(context.Context, string) (*tls.Certificate, error)) (*tls.Certificate, error) {
	now := c.now()
	c.mu.RLock()
	entry, hit := c.hits[name]
	missAt, miss := c.misses[name]
	c.mu.RUnlock()

	if hit {
		if now.Sub(entry.loadedAt) >= certificateCacheFreshFor {
			c.group.DoChan(name, func() (any, error) {
				return c.refresh(name, load)
			})
		}
		return entry.cert, nil
	}
	if miss && now.Sub(missAt) < certificateCacheMissFor {
		return nil, gorm.ErrRecordNotFound
	}

	result := c.group.DoChan(name, func() (any, error) {
		return c.refresh(name, load)
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-result:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*tls.Certificate), nil
	}
}

func (c *certificateCache) refresh(name string, load func(context.Context, string) (*tls.Certificate, error)) (*tls.Certificate, error) {
	c.mu.RLock()
	gen := c.gen
	c.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), certificateCacheLoadLimit)
	defer cancel()
	cert, err := load(ctx, name)
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()
	if gen != c.gen {
		return cert, err
	}
	switch {
	case err == nil:
		c.hits[name] = cachedCertificate{cert: cert, loadedAt: now}
		delete(c.misses, name)
	case errors.Is(err, gorm.ErrRecordNotFound):
		delete(c.hits, name)
		if len(c.misses) >= maxCachedCertificateMiss {
			c.misses = make(map[string]time.Time)
		}
		c.misses[name] = now
	default:
		if entry, ok := c.hits[name]; ok {
			entry.loadedAt = now
			c.hits[name] = entry
		}
	}
	return cert, err
}

func (c *certificateCache) invalidate(name string) {
	c.mu.Lock()
	delete(c.hits, name)
	delete(c.misses, name)
	c.gen++
	c.mu.Unlock()
	c.group.Forget(name)
}

func (c *certificateCache) invalidateAll() {
	c.mu.Lock()
	c.hits = make(map[string]cachedCertificate)
	c.misses = make(map[string]time.Time)
	c.gen++
	c.mu.Unlock()
}
