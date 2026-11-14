// Package outbound bounds every request the library sends to a server the
// application names: a client that carries a timeout and never follows a
// redirect, and a response read that stops at a cap.
package outbound

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Client returns a copy of c that answers a redirect as itself, so a token or
// an admin call never reaches a host nobody configured. It refuses a nil
// client and one without a Timeout: the library never waits without bound.
func Client(c *http.Client) (*http.Client, error) {
	if c == nil {
		return nil, errors.New("an HTTP client is required")
	}
	if c.Timeout <= 0 {
		return nil, errors.New("the HTTP client needs a Timeout")
	}
	cp := *c
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp, nil
}

// ParseURL parses raw as an absolute http or https URL with a host and no
// user info, query or fragment.
func ParseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("URL %q: %w", raw, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("URL %q must be absolute http(s) with a host and no user info, query or fragment", raw)
	}
	return u, nil
}

// Response is a status, its headers and a body read in full.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// Do sends req and reads at most limit bytes of the answer; a longer body is
// an error. A transport error keeps its cause but drops the URL's query.
func Do(c *http.Client, req *http.Request, limit int64) (out Response, err error) {
	resp, err := c.Do(req) //nolint:gosec // G704: the URL is one the application configured, never request input
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return Response{}, fmt.Errorf("%s %s: %w", req.Method, req.URL.Path, err)
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return Response{}, fmt.Errorf("%s %s: reading the body: %w", req.Method, req.URL.Path, err)
	}
	if int64(len(body)) > limit {
		return Response{}, fmt.Errorf("%s %s: body over %d bytes", req.Method, req.URL.Path, limit)
	}
	return Response{Status: resp.StatusCode, Header: resp.Header, Body: body}, nil
}
