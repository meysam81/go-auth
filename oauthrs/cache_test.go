package oauthrs_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/meysam81/go-auth/v2/oauthrs"
)

// clock is a settable Now.
type clock struct{ ns atomic.Int64 }

func newClock() *clock               { c := &clock{}; c.ns.Store(t0.UnixNano()); return c }
func (c *clock) now() time.Time      { return time.Unix(0, c.ns.Load()).UTC() }
func (c *clock) add(d time.Duration) { c.ns.Add(int64(d)) }
func cached(c *clock, ttl time.Duration, size int) func(*oauthrs.IntrospectorConfig) {
	return func(cfg *oauthrs.IntrospectorConfig) { cfg.Now, cfg.CacheTTL, cfg.CacheSize = c.now, ttl, size }
}

func TestIntrospector_CacheHitMissAndExpiry(t *testing.T) {
	t.Parallel()
	endpoint, hits := hydra(t, respond(http.StatusOK, answer(nil)))
	c := newClock()
	in := introspector(t, endpoint, cached(c, 30*time.Second, 0))
	steps := []struct {
		advance time.Duration
		token   string
		hits    int32
	}{
		{0, "a", 1},                // miss
		{29 * time.Second, "a", 1}, // hit
		{0, "b", 2},                // another token misses
		{time.Second, "a", 3},      // 30 s after it was cached: expired
	}
	for i, s := range steps {
		c.add(s.advance)
		if _, err := in.Verify(t.Context(), s.token); err != nil {
			t.Fatalf("step %d: Verify: %v", i, err)
		}
		if hits.Load() != s.hits {
			t.Fatalf("step %d: %d endpoint hits, want %d", i, hits.Load(), s.hits)
		}
	}
}

// A cached token never outlives its own exp, whatever the TTL.
func TestIntrospector_CacheStopsAtTheTokenExpiry(t *testing.T) {
	t.Parallel()
	endpoint, hits := hydra(t, respond(http.StatusOK, answer(func(a *answerJSON) { a.Exp = t0.Add(10 * time.Second).Unix() })))
	c := newClock()
	in := introspector(t, endpoint, cached(c, time.Minute, 0))
	if _, err := in.Verify(t.Context(), "a"); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	c.add(10 * time.Second)
	if _, err := in.Verify(t.Context(), "a"); !errors.Is(err, oauthrs.ErrInvalidToken) || hits.Load() != 2 {
		t.Fatalf("Verify at exp = %v after %d hits; want ErrInvalidToken from a fresh introspection", err, hits.Load())
	}
}

func TestIntrospector_CacheIsBoundedAndReturnsCopies(t *testing.T) {
	t.Parallel()
	endpoint, hits := hydra(t, respond(http.StatusOK, answer(nil)))
	in := introspector(t, endpoint, cached(newClock(), 30*time.Second, 2))
	for _, tok := range []string{"a", "b", "c", "a", "c"} { // a is evicted by c; c stays
		got, err := in.Verify(t.Context(), tok)
		if err != nil {
			t.Fatalf("Verify(%s): %v", tok, err)
		}
		got.Scopes[0] = "admin"
	}
	if hits.Load() != 4 {
		t.Fatalf("%d endpoint hits, want 4", hits.Load())
	}
	if got, err := in.Verify(t.Context(), "c"); err != nil || got.Scopes[0] != "read" {
		t.Fatalf("cached Scopes = %v, %v; a caller's edit reached the cache", got.Scopes, err)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// blocked is an endpoint that answers only once release is closed.
func blocked(hits *atomic.Int32, release <-chan struct{}) *http.Client {
	return &http.Client{Timeout: time.Minute, Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		hits.Add(1)
		select {
		case <-release:
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(answer(nil))), Request: r}, nil
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	})}
}

// Concurrent requests with one token share one introspection, and a waiter
// that hangs up neither fails the others nor cancels the call.
func TestIntrospector_ConcurrentVerifiesShareOneCall(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var hits atomic.Int32
		release := make(chan struct{})
		in := introspector(t, "http://hydra.test/admin/oauth2/introspect", func(c *oauthrs.IntrospectorConfig) {
			c.HTTPClient, c.CacheTTL = blocked(&hits, release), 30*time.Second
		})
		leader, hangUp := context.WithCancel(t.Context())
		leaderErr := make(chan error, 1)
		var wg sync.WaitGroup
		wg.Go(func() {
			_, err := in.Verify(leader, "tok")
			leaderErr <- err
		})
		synctest.Wait()
		const followers = 8
		errs := make(chan error, followers)
		for range followers {
			wg.Go(func() {
				_, err := in.Verify(t.Context(), "tok")
				errs <- err
			})
		}
		synctest.Wait()
		hangUp()
		if err := <-leaderErr; hits.Load() != 1 || !errors.Is(err, context.Canceled) {
			t.Fatalf("hits %d, leader err %v; want 1 and context.Canceled", hits.Load(), err)
		}
		close(release)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("follower: %v", err)
			}
		}
		if hits.Load() != 1 {
			t.Fatalf("%d endpoint hits, want 1", hits.Load())
		}
	})
}

// A refusal is never stored, so a stream of bad tokens cannot evict a
// verified one from a full cache.
func TestIntrospector_RefusalsDoNotEvictVerifiedTokens(t *testing.T) {
	t.Parallel()
	endpoint, hits := hydra(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		if r.PostForm.Get("token") == "good" {
			respond(http.StatusOK, answer(nil))(w, r)
			return
		}
		respond(http.StatusOK, `{"active":false}`)(w, r)
	})
	in := introspector(t, endpoint, cached(newClock(), 30*time.Second, 1))
	for _, step := range []struct {
		token string
		ok    bool
	}{{"good", true}, {"bad", false}, {"good", true}} {
		if _, err := in.Verify(t.Context(), step.token); (err == nil) != step.ok {
			t.Fatalf("Verify(%s) = %v", step.token, err)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("%d endpoint hits, want 2: the refusal evicted the verified token", hits.Load())
	}
}
