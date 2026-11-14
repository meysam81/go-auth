package oauthrs

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"
)

type key = [32]byte // sha256 of a token; the token itself is never kept

// cache holds verified tokens only, each until min(TTL, exp). It keeps at
// most size entries and evicts the oldest insertion first.
type cache struct {
	mu      sync.Mutex
	ttl     time.Duration
	size    int
	entries map[key]cacheEntry
	order   []key // insertion order; order[next] is the oldest once full
	next    int
}

type cacheEntry struct {
	tok     Token
	expires time.Time
}

func newCache(ttl time.Duration, size int) *cache {
	return &cache{ttl: ttl, size: size, entries: make(map[key]cacheEntry)}
}

func (c *cache) get(k key, now time.Time) (Token, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[k]
	if !ok || !now.Before(e.expires) {
		return Token{}, false
	}
	return e.tok.clone(), true
}

func (c *cache) put(k key, t Token, now time.Time) {
	expires := now.Add(c.ttl)
	if t.ExpiresAt.Before(expires) {
		expires = t.ExpiresAt
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[k]; !ok {
		if len(c.order) < c.size {
			c.order = append(c.order, k)
		} else {
			delete(c.entries, c.order[c.next])
			c.order[c.next] = k
			c.next = (c.next + 1) % c.size
		}
	}
	c.entries[k] = cacheEntry{tok: t.clone(), expires: expires}
}

func (t Token) clone() Token {
	t.Scopes, t.Audience, t.Ext = slices.Clone(t.Scopes), slices.Clone(t.Audience), slices.Clone(t.Ext)
	return t
}

// flight runs one introspection per token at a time. The call runs on a
// context that keeps the first caller's values but not its cancellation (the
// client's Timeout bounds it), and every waiter stops at its own context.
type flight struct {
	mu    sync.Mutex
	calls map[key]*call
}

type call struct {
	done chan struct{}
	tok  Token
	err  error
}

func (f *flight) do(ctx context.Context, k key, fn func(context.Context) (Token, error)) (Token, error) {
	f.mu.Lock()
	c, ok := f.calls[k]
	if !ok {
		if f.calls == nil {
			f.calls = make(map[key]*call)
		}
		c = &call{done: make(chan struct{})}
		f.calls[k] = c
		go f.run(context.WithoutCancel(ctx), k, c, fn)
	}
	f.mu.Unlock()
	select {
	case <-c.done:
		return c.tok.clone(), c.err
	case <-ctx.Done():
		return Token{}, fmt.Errorf("oauthrs: introspection: %w", context.Cause(ctx))
	}
}

func (f *flight) run(ctx context.Context, k key, c *call, fn func(context.Context) (Token, error)) {
	c.tok, c.err = fn(ctx)
	f.mu.Lock()
	delete(f.calls, k)
	f.mu.Unlock()
	close(c.done)
}
