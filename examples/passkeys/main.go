// Command passkeys is a runnable demo of the webauthn package: register a
// passkey, then sign in with it through browser autofill or a button.
//
// The stores are in memory and the "account" is just a name the visitor types.
// This is a demo, not production code: a real application authenticates the
// subject before registration and keeps credentials in a database.
//
//	go run ./examples/passkeys   # then open http://localhost:8080
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/meysam81/go-auth/v2/authtest"
	"github.com/meysam81/go-auth/v2/store"
	"github.com/meysam81/go-auth/v2/webauthn"
)

const (
	addr   = "localhost:8080"
	origin = "http://localhost:8080"
	rpID   = "localhost"

	// Purposes bind a flow to one ceremony: a flow begun for registration can
	// never be finished as a sign-in.
	purposeRegister = "register"
	purposeSignin   = "signin"

	maxBodyBytes = 128 << 10 // the library itself refuses responses over 64 KiB
	maxNameRunes = 64
)

//go:embed index.html
var indexHTML []byte

// server holds the relying party and its stores.
type server struct {
	rp    *webauthn.RP
	flows store.FlowStore
	store *authtest.MemoryWebAuthnStore
	log   *slog.Logger
}

// Request and response bodies.

type registerBeginRequest struct {
	Name string `json:"name"`
}

type signinBeginRequest struct {
	// Conditional asks for autofill (conditional mediation) instead of a modal prompt.
	Conditional bool `json:"conditional"`
}

type beginResponse struct {
	FlowID    string          `json:"flow_id"`
	Options   json.RawMessage `json:"options"`
	Mediation string          `json:"mediation"`
}

type registerFinishRequest struct {
	FlowID     string          `json:"flow_id"`
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

type signinFinishRequest struct {
	FlowID     string          `json:"flow_id"`
	Credential json.RawMessage `json:"credential"`
}

type subjectResponse struct {
	Subject string `json:"subject"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("passkeys example", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	rp, err := webauthn.New(webauthn.Config{
		RPID:    rpID,
		RPName:  "go-auth passkeys example",
		Origins: []string{origin},
	})
	if err != nil {
		return err
	}

	s := &server{
		rp:    rp,
		flows: authtest.NewMemoryFlowStore(time.Now),
		store: authtest.NewMemoryWebAuthnStore(),
		log:   log,
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Error("shutdown", "err", err)
		}
	}()

	log.Info("listening", "url", origin)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("POST /register/begin", s.registerBegin)
	mux.HandleFunc("POST /register/finish", s.registerFinish)
	mux.HandleFunc("POST /signin/begin", s.signinBegin)
	mux.HandleFunc("POST /signin/finish", s.signinFinish)
	return mux
}

func (s *server) index(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'")
	if _, err := w.Write(indexHTML); err != nil {
		s.log.Error("write page", "err", err)
	}
}

// registerBegin starts a registration. Demo only: the name the visitor types is
// the subject, so anyone can add a passkey to any existing name. In a real
// application that is an account takeover: register a passkey only for a
// subject the application has already authenticated.
func (s *server) registerBegin(w http.ResponseWriter, r *http.Request) {
	var req registerBeginRequest
	if !s.decode(w, r, &req) {
		return
	}
	name, ok := cleanName(req.Name)
	if !ok {
		s.fail(w, http.StatusBadRequest, "enter a name of 1 to 64 characters", nil)
		return
	}

	begun, err := s.rp.BeginRegistration(r.Context(), s.flows, s.store, s.store,
		webauthn.Subject{ID: name, Name: name, DisplayName: name},
		webauthn.RegistrationOptions{Kind: webauthn.Passkey, Purpose: purposeRegister})
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "something went wrong", err)
		return
	}
	s.json(w, http.StatusOK, beginResponse{FlowID: begun.FlowID, Options: begun.Options, Mediation: begun.Mediation})
}

// registerFinish completes a registration. The subject comes from the request
// body here only because the demo has no sessions. A real application takes it
// from its authenticated session, never from the request body.
func (s *server) registerFinish(w http.ResponseWriter, r *http.Request) {
	var req registerFinishRequest
	if !s.decode(w, r, &req) {
		return
	}
	name, ok := cleanName(req.Name)
	if !ok {
		s.fail(w, http.StatusBadRequest, "enter a name of 1 to 64 characters", nil)
		return
	}

	// The credential is passed through as the raw bytes the browser produced.
	_, err := s.rp.FinishRegistration(r.Context(), s.flows, s.store,
		webauthn.Expect{FlowID: req.FlowID, Purpose: purposeRegister, Subject: name},
		req.Credential)
	if err != nil {
		s.finishError(w, "registration failed", err)
		return
	}
	s.json(w, http.StatusOK, subjectResponse{Subject: name})
}

func (s *server) signinBegin(w http.ResponseWriter, r *http.Request) {
	var req signinBeginRequest
	if !s.decode(w, r, &req) {
		return
	}

	begun, err := s.rp.BeginPasskey(r.Context(), s.flows,
		webauthn.PasskeyOptions{Purpose: purposeSignin, Conditional: req.Conditional})
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "something went wrong", err)
		return
	}
	s.json(w, http.StatusOK, beginResponse{FlowID: begun.FlowID, Options: begun.Options, Mediation: begun.Mediation})
}

func (s *server) signinFinish(w http.ResponseWriter, r *http.Request) {
	var req signinFinishRequest
	if !s.decode(w, r, &req) {
		return
	}

	// A discoverable sign-in names no subject up front: the library resolves it
	// from the credential's user handle, so Expect.Subject stays empty.
	verified, err := s.rp.FinishPasskey(r.Context(), s.flows, s.store, s.store,
		webauthn.Expect{FlowID: req.FlowID, Purpose: purposeSignin},
		req.Credential)
	if err != nil {
		s.finishError(w, "sign-in failed", err)
		return
	}
	// A real application would start a session here.
	s.json(w, http.StatusOK, subjectResponse{Subject: verified.Subject})
}

// finishError logs the real error and answers with a fixed message: the
// library's error text is for logs, never for a client. failed names the
// ceremony ("registration failed" or "sign-in failed").
func (s *server) finishError(w http.ResponseWriter, failed string, err error) {
	switch {
	case errors.Is(err, store.ErrDuplicate):
		// FinishRegistration returns this when any subject already holds the
		// credential ID. Never resolve it by re-binding the credential.
		s.fail(w, http.StatusConflict, "that passkey is already registered", err)
	case errors.Is(err, webauthn.ErrUnknownCredential):
		// A real application would also call
		// PublicKeyCredential.signalUnknownCredential in the browser so the
		// credential manager can drop the stale passkey.
		s.fail(w, http.StatusUnauthorized, "unknown passkey", err)
	case errors.Is(err, webauthn.ErrInvalidCredentials), errors.Is(err, webauthn.ErrCloneSuspected):
		s.fail(w, http.StatusUnauthorized, failed, err)
	default:
		s.fail(w, http.StatusInternalServerError, "something went wrong", err)
	}
}

// decode reads a size-limited JSON body into dst. It answers 415 for any other
// content type, which also keeps cross-site form posts out, and 400 for a body
// that does not parse.
func (s *server) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		s.fail(w, http.StatusUnsupportedMediaType, "send application/json", nil)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		s.fail(w, http.StatusBadRequest, "invalid request", err)
		return false
	}
	return true
}

// fail logs err (when there is one) and writes a generic message.
func (s *server) fail(w http.ResponseWriter, status int, msg string, err error) {
	if err != nil {
		s.log.Warn("request failed", "status", status, "err", err)
	}
	s.json(w, status, errorResponse{Error: msg})
}

func (s *server) json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.log.Error("write response", "err", err)
	}
}

// cleanName trims a visitor-supplied name and reports whether it is usable.
func cleanName(in string) (string, bool) {
	name := strings.TrimSpace(in)
	n := utf8.RuneCountInString(name)
	return name, n >= 1 && n <= maxNameRunes
}
