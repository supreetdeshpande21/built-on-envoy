// Copyright Built On Envoy
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package oauth2te

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	evictReasonLRU     = "lru"
	evictReasonExpired = "expired"
)

type cachedToken struct {
	tokenType   string
	accessToken string
	expiresAt   time.Time
}

type lruItem struct {
	key   string
	value cachedToken
}

// tokenCache is a bounded in-process LRU of exchanged tokens with lazy TTL eviction.
type tokenCache struct {
	mu               sync.Mutex
	entries          map[string]*list.Element
	lru              *list.List // front = most recently used
	maxEntries       int
	now              func() time.Time
	pendingEvictions map[string]uint64
}

func newTokenCache(maxEntries int) *tokenCache {
	if maxEntries < 1 {
		maxEntries = 1
	}
	return &tokenCache{
		entries:          make(map[string]*list.Element, maxEntries),
		lru:              list.New(),
		maxEntries:       maxEntries,
		now:              time.Now,
		pendingEvictions: make(map[string]uint64, 2),
	}
}

func (c *tokenCache) drainEvictions() map[string]uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pendingEvictions) == 0 {
		return nil
	}
	out := c.pendingEvictions
	c.pendingEvictions = make(map[string]uint64, 2)
	return out
}

func (c *tokenCache) get(key string) (cachedToken, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.entries[key]
	if !ok {
		return cachedToken{}, false
	}
	item := el.Value.(*lruItem)
	if !c.now().Before(item.value.expiresAt) {
		c.removeElementLocked(el)
		c.pendingEvictions[evictReasonExpired]++
		return cachedToken{}, false
	}
	c.lru.MoveToFront(el)
	return item.value, true
}

func (c *tokenCache) set(key string, value cachedToken) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.entries[key]; ok {
		el.Value.(*lruItem).value = value
		c.lru.MoveToFront(el)
		return
	}

	el := c.lru.PushFront(&lruItem{key: key, value: value})
	c.entries[key] = el

	if c.lru.Len() > c.maxEntries {
		if back := c.lru.Back(); back != nil {
			c.removeElementLocked(back)
			c.pendingEvictions[evictReasonLRU]++
		}
	}
}

func (c *tokenCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

func (c *tokenCache) removeElementLocked(el *list.Element) {
	item := el.Value.(*lruItem)
	delete(c.entries, item.key)
	c.lru.Remove(el)
}

// cacheKey = hash(subject_token + audience + sorted(scopes))
func cacheKey(cfg *tokenExchangeConfig, subjectToken string) string {
	scopes := strings.Fields(cfg.Scope)
	sort.Strings(scopes)

	h := sha256.New()
	writeField := func(s string) {
		var lenBuf [8]byte
		n := len(s)
		for i := 0; i < 8; i++ {
			lenBuf[i] = byte(n >> (8 * i))
		}
		_, _ = h.Write(lenBuf[:])
		_, _ = h.Write([]byte(s))
	}
	writeField(subjectToken)
	writeField(cfg.Audience)
	writeField(strings.Join(scopes, " "))
	return hex.EncodeToString(h.Sum(nil))
}

// cacheLifetime returns min(expiresIn, ttlSeconds), or not-cacheable when <= 0.
func cacheLifetime(expiresIn int, cc *cacheConfig) (time.Duration, bool) {
	ttl := 0
	if cc.TTLSeconds > 0 {
		ttl = cc.TTLSeconds
	}
	if expiresIn > 0 && (ttl == 0 || expiresIn < ttl) {
		ttl = expiresIn
	}
	if ttl <= 0 {
		return 0, false
	}
	return time.Duration(ttl) * time.Second, true
}
