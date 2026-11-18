// Copyright Built On Envoy
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package oauth2te

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestCache(maxEntries int, clk *fakeClock) *tokenCache {
	c := newTokenCache(maxEntries)
	c.now = clk.now
	return c
}

func TestCacheHitAndMiss(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(8, clk)

	_, ok := c.get("k1")
	assert.False(t, ok)

	c.set("k1", cachedToken{tokenType: "Bearer", accessToken: "tok", expiresAt: clk.now().Add(time.Minute)})
	got, ok := c.get("k1")
	require.True(t, ok)
	assert.Equal(t, "Bearer", got.tokenType)
	assert.Equal(t, "tok", got.accessToken)
}

func TestCacheExpiry(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(8, clk)

	c.set("k1", cachedToken{tokenType: "Bearer", accessToken: "tok", expiresAt: clk.now().Add(30 * time.Second)})

	clk.advance(29 * time.Second)
	_, ok := c.get("k1")
	assert.True(t, ok)

	clk.advance(2 * time.Second)
	_, ok = c.get("k1")
	assert.False(t, ok)
	assert.Equal(t, uint64(1), c.drainEvictions()[evictReasonExpired])
	assert.Equal(t, 0, c.len())
}

func TestCacheLRUEviction(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(2, clk)
	exp := clk.now().Add(time.Hour)

	c.set("a", cachedToken{accessToken: "a", expiresAt: exp})
	c.set("b", cachedToken{accessToken: "b", expiresAt: exp})
	_, ok := c.get("a")
	require.True(t, ok)

	c.set("c", cachedToken{accessToken: "c", expiresAt: exp})

	assert.Equal(t, 2, c.len())
	_, ok = c.get("b")
	assert.False(t, ok)
	_, ok = c.get("a")
	assert.True(t, ok)
	_, ok = c.get("c")
	assert.True(t, ok)
	assert.Equal(t, uint64(1), c.drainEvictions()[evictReasonLRU])
}

func TestCacheSetUpdatesExisting(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(8, clk)
	exp := clk.now().Add(time.Hour)

	c.set("k", cachedToken{accessToken: "v1", expiresAt: exp})
	c.set("k", cachedToken{accessToken: "v2", expiresAt: exp})
	assert.Equal(t, 1, c.len())
	got, ok := c.get("k")
	require.True(t, ok)
	assert.Equal(t, "v2", got.accessToken)
}

func TestCacheKeyIsolation(t *testing.T) {
	base := &tokenExchangeConfig{Audience: "aud1", Scope: "write read"}
	otherAud := *base
	otherAud.Audience = "aud2"
	otherScope := *base
	otherScope.Scope = "read write" // same scopes, different order → same key

	k1 := cacheKey(base, "subjectA")
	k2 := cacheKey(&otherAud, "subjectA")
	k3 := cacheKey(base, "subjectB")
	k4 := cacheKey(&otherScope, "subjectA")

	assert.Equal(t, k1, k4, "sorted scopes must produce the same key")
	assert.Equal(t, k1, cacheKey(base, "subjectA"))
	assert.NotEqual(t, k1, k2)
	assert.NotEqual(t, k1, k3)
	assert.NotContains(t, k1, "subjectA")
}

func TestCacheLifetime(t *testing.T) {
	tests := []struct {
		name      string
		expiresIn int
		cc        *cacheConfig
		wantOK    bool
		wantTTL   time.Duration
	}{
		{"expires_in smaller than ttl", 100, &cacheConfig{TTLSeconds: 300}, true, 100 * time.Second},
		{"ttl smaller than expires_in", 10000, &cacheConfig{TTLSeconds: 300}, true, 300 * time.Second},
		{"no expires_in uses ttl", 0, &cacheConfig{TTLSeconds: 300}, true, 300 * time.Second},
		{"no bound", 0, &cacheConfig{TTLSeconds: 0}, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ttl, ok := cacheLifetime(tt.expiresIn, tt.cc)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.wantTTL, ttl)
			}
		})
	}
}
