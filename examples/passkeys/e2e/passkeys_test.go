// Package e2e drives examples/passkeys in a real Chrome with a virtual
// authenticator: the page's JavaScript, the browser's WebAuthn implementation
// and the webauthn package meet exactly as they do for a visitor.
//
// The library's own tests build ceremonies from the authtest virtual
// authenticator, which encodes responses the way this module expects them.
// Only a browser can show that what a browser sends — through
// PublicKeyCredential.toJSON and the parse*OptionsFromJSON helpers — is what
// the library accepts.
//
// It lives in its own module so the browser driver never enters the library's
// dependency graph. Run it with
//
//	cd examples/passkeys/e2e && go test ./...
//
// It needs Chrome or Chromium, named by CHROME_PATH or found on PATH. Without
// one the test skips, except when CI is true, where it fails.
package e2e

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
)

// The example listens on a fixed address; its relying party is bound to it.
const (
	exampleAddr = "localhost:8080"
	exampleURL  = "http://" + exampleAddr + "/"
)

func TestPasskeyInChrome(t *testing.T) {
	chrome := chromePath(t)
	bin := buildExample(t)
	startExample(t, bin)

	// A device-bound key (BE=0) and a synced passkey (BE=1, BS=1): the library
	// stores and checks the backup flags, and the two must both work.
	for _, tc := range []struct {
		name   string
		synced bool
	}{
		{name: "device-bound", synced: false},
		{name: "synced", synced: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newBrowser(t, chrome)
			authenticator := addAuthenticator(t, ctx, tc.synced)
			account := "visitor-" + tc.name
			signedIn := "Signed in as " + account

			run(t, ctx, "open the page", chromedp.Navigate(exampleURL))
			watchStatus(t, ctx)

			run(t, ctx, "register",
				chromedp.SendKeys("#register-name", account, chromedp.ByQuery),
				chromedp.Click("#register-form button", chromedp.ByQuery),
			)
			waitStatus(t, ctx, "Registered a passkey for "+account+". Now sign in.", 1, "registration")

			creds := credentials(t, ctx, authenticator)
			if len(creds) != 1 {
				t.Fatalf("the authenticator holds %d credentials after registration, want 1", len(creds))
			}
			if !creds[0].IsResidentCredential || creds[0].RpID != "localhost" {
				t.Fatalf("want a discoverable credential for localhost, got resident=%v rp=%q",
					creds[0].IsResidentCredential, creds[0].RpID)
			}
			// After registering, the page arms autofill (conditional mediation).
			// A virtual authenticator with presence simulation answers it without
			// a visitor picking the passkey, so the page signs in by itself, and
			// again each time it re-arms. Each success is shown only after the
			// server verified the assertion, so two of them prove that the
			// counter and backup state the first one stored are what the next
			// one accepts.
			waitStatus(t, ctx, signedIn, 2, "autofill sign-in")

			// The button: a modal request. Autofill is stopped for good first
			// (the page would re-arm it after the modal and sign in again with the
			// same message), and any sign-in already in flight is let finish, so
			// what follows the click is the modal ceremony alone: exactly one
			// assertion and one success.
			run(t, ctx, "stop autofill",
				chromedp.Evaluate(`startAutofill = () => {}; abortAutofill();`, nil))
			before := settle(t, ctx, authenticator)
			resetStatusLog(t, ctx)
			run(t, ctx, "sign in with the button", chromedp.Click("#signin", chromedp.ByQuery))
			waitStatus(t, ctx, signedIn, 1, "button sign-in")
			if n := signCount(t, ctx, authenticator); n != before+1 {
				t.Fatalf("button sign-in: the authenticator signed %d assertions, want 1", n-before)
			}
			if log := statusLog(t, ctx); len(log) != 1 {
				t.Fatalf("button sign-in: the page showed %+v, want one success", log)
			}
		})
	}
}

// chromePath names the browser to drive, or skips the test when there is none
// outside CI.
func chromePath(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("CHROME_PATH"); path != "" {
		return path
	}
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	if ci, err := strconv.ParseBool(os.Getenv("CI")); err == nil && ci {
		t.Fatal("no Chrome or Chromium found; CI must run this test, so install one or set CHROME_PATH")
	}
	t.Skip("no Chrome or Chromium found; set CHROME_PATH to run this test")
	return ""
}

// buildExample compiles examples/passkeys from the tree this module sits in.
func buildExample(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "passkeys")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "./examples/passkeys")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build the example: %v\n%s", err, out)
	}
	return bin
}

// startExample runs the example until the test ends and waits for it to serve.
// It refuses to start when the address is taken: the test would otherwise
// drive whatever already listens there, not the tree under test.
func startExample(t *testing.T, bin string) {
	t.Helper()
	ln, err := net.Listen("tcp", exampleAddr)
	if err != nil {
		t.Fatalf("%s is in use, and the example must listen there: %v", exampleAddr, err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin)
	dieWithParent(cmd)
	logs := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start the example: %v", err)
	}
	exited := make(chan struct{})
	var waitErr error
	exitReported := false
	var wg sync.WaitGroup
	wg.Go(func() {
		waitErr = cmd.Wait()
		close(exited)
	})
	t.Cleanup(func() {
		select {
		case <-exited:
			if !exitReported {
				t.Errorf("the example exited during the test: %v", waitErr)
			}
		default:
		}
		cancel()
		wg.Wait()
		if t.Failed() {
			t.Logf("example output:\n%s", logs.String())
		}
	})

	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(15 * time.Second)
	for {
		select {
		case <-exited:
			exitReported = true
			t.Fatalf("the example exited before serving: %v\n%s", waitErr, logs.String())
		default:
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, exampleURL, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		res, err := client.Do(req)
		if err == nil {
			if cerr := res.Body.Close(); cerr != nil {
				t.Fatal(cerr)
			}
			if res.StatusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the example did not serve %s within 15s (last error: %v)\n%s", exampleURL, err, logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// lockedBuffer collects the example's output; the process writes it while the
// test may read it.
type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// newBrowser starts a headless browser for one subtest.
func newBrowser(t *testing.T, chrome string) context.Context {
	t.Helper()
	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	opts = append(opts, chromedp.ExecPath(chrome))
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancelCtx := chromedp.NewContext(allocCtx)
	ctx, cancelTimeout := context.WithTimeout(ctx, 60*time.Second)
	t.Cleanup(func() {
		cancelTimeout()
		cancelCtx()
		cancelAlloc()
	})
	return ctx
}

// addAuthenticator attaches a CTAP2 platform authenticator that holds
// discoverable credentials, verifies the user, and answers presence checks.
func addAuthenticator(t *testing.T, ctx context.Context, synced bool) webauthn.AuthenticatorID {
	t.Helper()
	var id webauthn.AuthenticatorID
	run(t, ctx, "add a virtual authenticator",
		webauthn.Enable(),
		chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			id, err = webauthn.AddVirtualAuthenticator(&webauthn.VirtualAuthenticatorOptions{
				Protocol:                    webauthn.AuthenticatorProtocolCtap2,
				Ctap2version:                webauthn.Ctap2versionCtap21,
				Transport:                   webauthn.AuthenticatorTransportInternal,
				HasResidentKey:              true,
				HasUserVerification:         true,
				IsUserVerified:              true,
				AutomaticPresenceSimulation: true,
				DefaultBackupEligibility:    synced,
				DefaultBackupState:          synced,
			}).Do(ctx)
			return err
		}),
	)
	return id
}

func credentials(t *testing.T, ctx context.Context, id webauthn.AuthenticatorID) []*webauthn.Credential {
	t.Helper()
	var creds []*webauthn.Credential
	run(t, ctx, "list the authenticator's credentials", chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		creds, err = webauthn.GetCredentials(id).Do(ctx)
		return err
	}))
	return creds
}

// signCount is the counter of the authenticator's one credential.
func signCount(t *testing.T, ctx context.Context, id webauthn.AuthenticatorID) int64 {
	t.Helper()
	creds := credentials(t, ctx, id)
	if len(creds) != 1 {
		t.Fatalf("the authenticator holds %d credentials, want 1", len(creds))
	}
	return creds[0].SignCount
}

// settle waits until neither the counter nor the status line has moved for
// half a second, and returns the counter.
func settle(t *testing.T, ctx context.Context, id webauthn.AuthenticatorID) int64 {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	count, entries := signCount(t, ctx, id), len(statusLog(t, ctx))
	for quietSince := time.Now(); time.Since(quietSince) < 500*time.Millisecond; {
		if time.Now().After(deadline) {
			t.Fatal("the page kept signing in after autofill was stopped")
		}
		time.Sleep(100 * time.Millisecond)
		n, e := signCount(t, ctx, id), len(statusLog(t, ctx))
		if n != count || e != entries {
			count, entries, quietSince = n, e, time.Now()
		}
	}
	return count
}

// pageStatus is one message the example's page showed.
type pageStatus struct {
	Text  string `json:"text"`
	Error bool   `json:"error"`
}

// watchStatus records every message the page shows in window.__status, by
// wrapping the page's own say(): a message overwritten a moment later, or in
// the same task, is still seen.
func watchStatus(t *testing.T, ctx context.Context) {
	t.Helper()
	var initial pageStatus
	run(t, ctx, "watch the status line", chromedp.Evaluate(`(() => {
		const s = document.getElementById("status");
		window.__status = [];
		const shown = say;
		say = (text, isError) => {
			window.__status.push({ text: String(text), error: Boolean(isError) });
			shown(text, isError);
		};
		return { text: s.textContent, error: s.classList.contains("error") };
	})()`, &initial))
	// Navigate returns after the load event, and the page reports a browser it
	// cannot use while loading, so a refusal is already on screen.
	if initial.Error {
		t.Fatalf("the page refused the browser: %q", initial.Text)
	}
}

func resetStatusLog(t *testing.T, ctx context.Context) {
	t.Helper()
	run(t, ctx, "reset the status log", chromedp.Evaluate(`window.__status = []`, nil))
}

func statusLog(t *testing.T, ctx context.Context) []pageStatus {
	t.Helper()
	var log []pageStatus
	run(t, ctx, "read the status log", chromedp.Evaluate(`window.__status`, &log))
	return log
}

// waitStatus waits until the page has shown want at least n times, and fails
// as soon as it has shown an error.
func waitStatus(t *testing.T, ctx context.Context, want string, n int, what string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		log := statusLog(t, ctx)
		seen := 0
		for _, st := range log {
			if st.Error {
				t.Fatalf("%s: the page reported an error: %q (messages so far: %+v)", what, st.Text, log)
			}
			if st.Text == want {
				seen++
			}
		}
		if seen >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: the page showed %q %d times in 15s, want %d; it showed %+v", what, want, seen, n, log)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func run(t *testing.T, ctx context.Context, what string, actions ...chromedp.Action) {
	t.Helper()
	if err := chromedp.Run(ctx, actions...); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%s: the browser did not finish within the test's 60s", what)
		}
		t.Fatalf("%s: %v", what, fmt.Errorf("chromedp: %w", err))
	}
}
