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
// It needs Chrome or Chromium: on PATH, or named by CHROME_PATH. Without one
// the test skips, except under CI, where it fails.
package e2e

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
)

// The example listens on a fixed address; its relying party is bound to it.
const exampleURL = "http://localhost:8080/"

func TestPasskeyInChrome(t *testing.T) {
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
			ctx := newBrowser(t)
			authenticator := addAuthenticator(t, ctx, tc.synced)
			account := "visitor-" + tc.name
			signedIn := "Signed in as " + account

			// The page reports a browser it cannot use on load; Navigate returns
			// after the load event, so a refusal is already on screen.
			run(t, ctx, "open the page", chromedp.Navigate(exampleURL))
			watchStatus(t, ctx)

			run(t, ctx, "register",
				chromedp.SendKeys("#register-name", account, chromedp.ByQuery),
				chromedp.Click("#register-form button", chromedp.ByQuery),
			)
			waitStatus(t, ctx, "Registered a passkey for "+account+". Now sign in.", "registration")

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
			// keeps doing so each time it re-arms. Two sign-ins prove that the
			// counter and backup state the first one stored are what the next
			// one accepts.
			waitSignIns(t, ctx, authenticator, 2, signedIn, "autofill sign-in")

			// The button: a modal request with no autofill pending. The page
			// re-arms autofill only after the modal ceremony has finished, so the
			// first status change after the click is the modal result.
			run(t, ctx, "stop autofill", chromedp.Evaluate(`abortAutofill()`, nil))
			resetStatusLog(t, ctx)
			run(t, ctx, "sign in with the button", chromedp.Click("#signin", chromedp.ByQuery))
			waitStatus(t, ctx, signedIn, "button sign-in")
			if first := statusLog(t, ctx)[0]; first.Text != signedIn {
				t.Fatalf("button sign-in: the first status after the click was %q, want %q", first.Text, signedIn)
			}
		})
	}
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
func startExample(t *testing.T, bin string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin)
	var logs strings.Builder
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start the example: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		if err := cmd.Wait(); err != nil && ctx.Err() == nil {
			t.Errorf("the example exited: %v", err)
		}
		if t.Failed() {
			t.Logf("example output:\n%s", logs.String())
		}
	})

	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(15 * time.Second)
	for {
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

// newBrowser starts a headless browser for one subtest.
func newBrowser(t *testing.T) context.Context {
	t.Helper()
	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	if path := os.Getenv("CHROME_PATH"); path != "" {
		opts = append(opts, chromedp.ExecPath(path))
	} else if findChrome() == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("no Chrome or Chromium found; CI must run this test, so install one or set CHROME_PATH")
		}
		t.Skip("no Chrome or Chromium found; set CHROME_PATH to run this test")
	}
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

// findChrome reports the first browser chromedp would find on PATH.
func findChrome() string {
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
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

// pageStatus is one state of the example's status line.
type pageStatus struct {
	Text  string `json:"text"`
	Error bool   `json:"error"`
}

// watchStatus records every change of the status line in window.__status, so
// a message the page overwrites a moment later is still seen.
func watchStatus(t *testing.T, ctx context.Context) {
	t.Helper()
	var initial pageStatus
	run(t, ctx, "watch the status line", chromedp.Evaluate(`(() => {
		const s = document.getElementById("status");
		const read = () => ({ text: s.textContent, error: s.classList.contains("error") });
		window.__status = [];
		new MutationObserver(() => window.__status.push(read())).observe(s, {
			childList: true, characterData: true, subtree: true, attributes: true,
		});
		return read();
	})()`, &initial))
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

// waitStatus waits until the status line has read want, and fails as soon as
// it has shown an error.
func waitStatus(t *testing.T, ctx context.Context, want, what string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		log := statusLog(t, ctx)
		for _, st := range log {
			if st.Error {
				t.Fatalf("%s: the page reported an error: %q", what, st.Text)
			}
		}
		for _, st := range log {
			if st.Text == want {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: the status line never read %q in 15s; it read %+v", what, want, log)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// waitSignIns waits until the authenticator has signed n assertions and the
// page has shown want, failing on any error the page showed meanwhile.
func waitSignIns(t *testing.T, ctx context.Context, id webauthn.AuthenticatorID, n int64, want, what string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		waitStatus(t, ctx, want, what)
		creds := credentials(t, ctx, id)
		if len(creds) == 1 && creds[0].SignCount >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: the authenticator signed fewer than %d assertions in 15s", what, n)
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
		t.Fatalf("%s: %v", what, err)
	}
}
