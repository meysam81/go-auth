package hydra

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/meysam81/go-auth/v2/internal/outbound"
)

const maxAnswerBytes = 1 << 20

// ErrInvalidChallenge is every refusal of a login or consent challenge: an
// empty one, and one Hydra does not know or reports as answered or expired.
var ErrInvalidChallenge = errors.New("hydra: invalid challenge")

// failure matches ErrInvalidChallenge and carries a reason for logs only.
type failure struct{ reason string }

func (f *failure) Error() string { return ErrInvalidChallenge.Error() + ": " + f.reason }

// Is reports whether target is ErrInvalidChallenge.
func (f *failure) Is(target error) bool { return target == ErrInvalidChallenge }

// statusError is a non-2xx answer; it matches no sentinel.
type statusError struct {
	method, path string
	status       int
}

func (e *statusError) Error() string {
	return fmt.Sprintf("hydra: %s %s: status %d", e.method, e.path, e.status)
}

// Config configures the admin client.
type Config struct {
	AdminURL   string       // the admin API's base URL, such as http://hydra-admin:4445
	HTTPClient *http.Client // required, with a Timeout; never follows a redirect
}

// Client calls the Hydra admin API.
type Client struct {
	base   string
	client *http.Client
}

// New validates cfg.
func New(cfg Config) (*Client, error) {
	base, err := outbound.ParseURL(cfg.AdminURL)
	if err != nil {
		return nil, fmt.Errorf("hydra: AdminURL: %w", err)
	}
	client, err := outbound.Client(cfg.HTTPClient)
	if err != nil {
		return nil, fmt.Errorf("hydra: %w", err)
	}
	return &Client{base: strings.TrimSuffix(base.String(), "/"), client: client}, nil
}

// do sends one admin request with in as its JSON body when set, and decodes a
// 2xx answer into out when set. path is already escaped.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, in, out any) (http.Header, error) {
	target := c.base + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var body io.Reader = http.NoBody
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, fmt.Errorf("hydra: %s %s: %w", method, path, err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, fmt.Errorf("hydra: %s %s: %w", method, path, err)
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := outbound.Do(c.client, req, maxAnswerBytes)
	if err != nil {
		return nil, fmt.Errorf("hydra: %w", err)
	}
	if resp.Status < 200 || resp.Status > 299 {
		return nil, &statusError{method: method, path: path, status: resp.Status}
	}
	if out != nil {
		if err := json.Unmarshal(resp.Body, out); err != nil {
			return nil, fmt.Errorf("hydra: %s %s: answer: %w", method, path, err)
		}
	}
	return resp.Header, nil
}

// onChallenge sends one request about a login or consent challenge and maps
// Hydra's answers for an unknown challenge (404) to ErrInvalidChallenge. 409
// and 410 map to it too, defensively: Hydra answers 404 for an unknown
// challenge and accepts a repeated answer with a redirect.
func (c *Client) onChallenge(ctx context.Context, method, path, param, challenge string, in, out any) error {
	if challenge == "" {
		return &failure{reason: "empty " + param}
	}
	_, err := c.do(ctx, method, path, url.Values{param: {challenge}}, in, out)
	var se *statusError
	if errors.As(err, &se) && (se.status == http.StatusNotFound || se.status == http.StatusConflict || se.status == http.StatusGone) {
		return &failure{reason: se.Error()}
	}
	return err
}

// answer sends an accept or reject and returns where Hydra sends the browser.
func (c *Client) answer(ctx context.Context, path, param, challenge string, in any) (string, error) {
	var out struct {
		RedirectTo string `json:"redirect_to"`
	}
	if err := c.onChallenge(ctx, http.MethodPut, path, param, challenge, in, &out); err != nil {
		return "", err
	}
	if out.RedirectTo == "" {
		return "", fmt.Errorf("hydra: PUT %s: answer has no redirect_to", path)
	}
	return out.RedirectTo, nil
}
