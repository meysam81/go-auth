package oauthrs

import (
	"net/http"
	"net/url"
	"strings"
)

// maxTokenLen bounds a token before it reaches a cache key or a request.
const maxTokenLen = 4096

// BearerToken returns the token in r's Authorization header (RFC 6750
// section 2.1); the scheme matches case-insensitively. It never reads the
// body, so a form-encoded token is never seen. A token in the URI query is
// refused, header or not: the URL has already reached a log.
func BearerToken(r *http.Request) (string, error) {
	if r.URL != nil && queryHasAccessToken(r.URL.RawQuery) {
		return "", fail("access_token in the URI query")
	}
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", fail("want exactly one Authorization header")
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", fail("Authorization scheme is not Bearer")
	}
	token = strings.TrimLeft(token, " ")
	if !validToken(token) {
		return "", fail("bearer token is not a b64token of at most 4096 bytes")
	}
	return token, nil
}

// queryHasAccessToken scans the raw query for an access_token key. It does not
// use url.Values: Query() drops a pair it cannot parse, such as
// "access_token=x;" or "access_token=x%", and a dropped pair must not hide the
// token. Both & and ; separate pairs, so no server's reading of the query can
// see a key this scan does not.
func queryHasAccessToken(raw string) bool {
	for pair := range strings.FieldsFuncSeq(raw, func(r rune) bool { return r == '&' || r == ';' }) {
		key, _, _ := strings.Cut(pair, "=")
		if unescaped, err := url.QueryUnescape(key); err == nil {
			key = unescaped
		}
		if key == "access_token" {
			return true
		}
	}
	return false
}

// validToken reports whether s is a b64token (RFC 6750 section 2.1) of at
// most maxTokenLen bytes.
func validToken(s string) bool {
	if s == "" || len(s) > maxTokenLen || s[0] == '=' {
		return false
	}
	padding := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '=':
			padding = true
		case padding:
			return false
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9',
			c == '-', c == '.', c == '_', c == '~', c == '+', c == '/':
		default:
			return false
		}
	}
	return true
}
