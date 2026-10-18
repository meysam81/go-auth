package webauthn_test

import (
	"context"
	"fmt"

	"github.com/meysam81/go-auth/v2/authtest"
	"github.com/meysam81/go-auth/v2/store"
	"github.com/meysam81/go-auth/v2/webauthn"
)

const (
	exampleOrigin = "https://app.example.test"
	exampleSub    = "user-1"
)

// exampleEnv wires a relying party to in-memory stores, with a virtual
// authenticator standing in for the browser and the user's passkey.
type exampleEnv struct {
	rp    *webauthn.RP
	flows store.FlowStore
	creds *authtest.MemoryWebAuthnStore
	key   *authtest.Authenticator
}

func newExampleEnv() (*exampleEnv, error) {
	rp, err := webauthn.New(webauthn.Config{
		RPID:    "example.test",
		RPName:  "Example",
		Origins: []string{exampleOrigin},
	})
	if err != nil {
		return nil, err
	}
	key, err := authtest.NewAuthenticator(authtest.AuthenticatorConfig{
		UserVerified:   true,
		Discoverable:   true,
		BackupEligible: true,
	})
	if err != nil {
		return nil, err
	}
	return &exampleEnv{rp: rp, flows: authtest.NewMemoryFlowStore(nil), creds: authtest.NewMemoryWebAuthnStore(), key: key}, nil
}

// register enrolls the passkey for exampleSub, as the registration example does.
func (e *exampleEnv) register(ctx context.Context, kind webauthn.CredentialKind) error {
	sub := webauthn.Subject{ID: exampleSub, Name: "user@example.test"}
	begun, err := e.rp.BeginRegistration(ctx, e.flows, e.creds, e.creds, sub,
		webauthn.RegistrationOptions{Kind: kind, Purpose: "enroll"})
	if err != nil {
		return err
	}
	response, err := e.key.Register(begun.Options, exampleOrigin)
	if err != nil {
		return err
	}
	_, err = e.rp.FinishRegistration(ctx, e.flows, e.creds,
		webauthn.Expect{FlowID: begun.FlowID, Purpose: "enroll", Subject: exampleSub}, response)
	return err
}

func ExampleRP_BeginRegistration() {
	ctx := context.Background()
	env, err := newExampleEnv()
	if err != nil {
		fmt.Println(err)
		return
	}

	// The user is already signed in. Begin returns the options for the browser
	// (navigator.credentials.create) and a flow ID to keep in the session.
	sub := webauthn.Subject{ID: exampleSub, Name: "user@example.test"}
	begun, err := env.rp.BeginRegistration(ctx, env.flows, env.creds, env.creds, sub,
		webauthn.RegistrationOptions{Kind: webauthn.Passkey, Purpose: "enroll"})
	if err != nil {
		fmt.Println(err)
		return
	}

	// Here the browser asks the authenticator to create the credential and
	// posts back PublicKeyCredential.toJSON(). The virtual authenticator
	// plays that part.
	response, err := env.key.Register(begun.Options, exampleOrigin)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Finish verifies the response; persist nothing yourself, the
	// CredentialStore already holds the new credential.
	cred, err := env.rp.FinishRegistration(ctx, env.flows, env.creds,
		webauthn.Expect{FlowID: begun.FlowID, Purpose: "enroll", Subject: sub.ID}, response)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("registered:", cred.Subject == sub.ID)
	fmt.Println("backup eligible:", cred.BackupEligible)
	// Output:
	// registered: true
	// backup eligible: true
}

func ExampleRP_BeginPasskey() {
	ctx := context.Background()
	env, err := newExampleEnv()
	if err != nil {
		fmt.Println(err)
		return
	}
	if err = env.register(ctx, webauthn.Passkey); err != nil {
		fmt.Println(err)
		return
	}

	// Nobody is signed in yet, so Begin takes no identifier: the browser
	// offers whichever passkeys it holds for this site.
	begun, err := env.rp.BeginPasskey(ctx, env.flows, webauthn.PasskeyOptions{Purpose: "login"})
	if err != nil {
		fmt.Println(err)
		return
	}

	// The browser signs in with navigator.credentials.get; the virtual
	// authenticator answers with the user handle it remembered.
	response, err := env.key.Assert(begun.Options, exampleOrigin)
	if err != nil {
		fmt.Println(err)
		return
	}

	// The subject comes from the assertion, so Expect names none. Issue the
	// session from the verified facts.
	verified, err := env.rp.FinishPasskey(ctx, env.flows, env.creds, env.creds,
		webauthn.Expect{FlowID: begun.FlowID, Purpose: "login"}, response)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("subject:", verified.Subject)
	fmt.Println("methods:", verified.Methods)
	// Output:
	// subject: user-1
	// methods: [swk mfa]
}

func ExampleRP_BeginSecondFactor() {
	ctx := context.Background()
	env, err := newExampleEnv()
	if err != nil {
		fmt.Println(err)
		return
	}
	if err = env.register(ctx, webauthn.SecurityKey); err != nil {
		fmt.Println(err)
		return
	}

	// The password step already identified the subject, so the options list
	// exactly that subject's credentials. RequireUV asks for a PIN or
	// biometric; leave it off to accept a touch alone.
	begun, err := env.rp.BeginSecondFactor(ctx, env.flows, env.creds, env.creds, exampleSub,
		webauthn.SecondFactorOptions{Purpose: "login", RequireUV: true})
	if err != nil {
		fmt.Println(err)
		return
	}

	response, err := env.key.Assert(begun.Options, exampleOrigin)
	if err != nil {
		fmt.Println(err)
		return
	}

	verified, err := env.rp.FinishSecondFactor(ctx, env.flows, env.creds,
		webauthn.Expect{FlowID: begun.FlowID, Purpose: "login", Subject: exampleSub}, response)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("subject:", verified.Subject)
	fmt.Println("user verified:", verified.UserVerified)
	fmt.Println("methods:", verified.Methods)
	// Output:
	// subject: user-1
	// user verified: true
	// methods: [swk mfa]
}
