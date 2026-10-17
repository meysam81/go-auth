package amr

import (
	"maps"
	"time"
)

// Method is an authentication method reference: an RFC 8176 value or one the
// application defines.
type Method string

// RFC 8176 values the library issues or interprets.
const (
	PWD Method = "pwd" // password
	OTP Method = "otp" // one-time password (RFC 4226/6238)
	HWK Method = "hwk" // WebAuthn assertion, credential not backup-eligible (BE=0)
	SWK Method = "swk" // WebAuthn assertion, backup-eligible credential (BE=1)
	MFA Method = "mfa" // the WebAuthn assertion itself verified the user (UV=1)
)

// Class is the kind of proof a method offers.
type Class uint8

// Factor classes.
const (
	Unknown    Class = iota // counts for nothing
	Knowledge               // pwd
	Possession              // otp, hwk, swk, application codes
	Federated               // an upstream identity provider; the application decides what it vouches for
)

// Factor describes one method. PhishingResistant is true only for methods
// whose proof is bound to the origin (WebAuthn).
type Factor struct {
	Class             Class
	PhishingResistant bool
}

// Policy classifies every method the application issues. A method absent
// from Factors counts for nothing: unknown is never a pass.
//
// MFA is a modifier, not a factor: it is never classified, and it counts only
// beside HWK or SWK.
type Policy struct{ Factors map[Method]Factor }

// Standard classifies the RFC 8176 values above. Applications extend a copy
// with their own methods (a recovery code, an emailed code, a federated login).
// Each call returns an independent policy.
func Standard() Policy {
	return Policy{Factors: map[Method]Factor{
		PWD: {Class: Knowledge},
		OTP: {Class: Possession},
		HWK: {Class: Possession, PhishingResistant: true},
		SWK: {Class: Possession, PhishingResistant: true},
	}}
}

// With returns a copy of the policy that also classifies m as f. The receiver
// is not modified. MFA is a modifier and can never be a factor, so classifying
// it is ignored.
func (p Policy) With(m Method, f Factor) Policy {
	factors := maps.Clone(p.Factors)
	if factors == nil {
		factors = make(map[Method]Factor, 1)
	}
	if m != MFA {
		factors[m] = f
	}
	return Policy{Factors: factors}
}

// Requirement is the strength a session must show.
type Requirement uint8

// Requirements. The zero value is not a requirement, so an unset one never
// passes.
const (
	AnyFactor         Requirement = iota + 1
	MultiFactor                   // a first factor plus a possession factor, or one WebAuthn assertion with mfa
	PhishingResistant             // MultiFactor with a phishing-resistant method among them
)

// Satisfies reports whether methods meet r. Methods the policy does not
// classify count for nothing, and an undefined Requirement is never satisfied.
//
// A first factor is a Knowledge or Federated method. MultiFactor needs a first
// factor plus a Possession method, never two first factors; or MFA beside HWK
// or SWK from the same assertion, where HWK or SWK is classified Possession.
// MFA alone is nothing.
//
// A flat set cannot say which assertion MFA came from, so it must hold only
// methods this application verified itself. Never copy an upstream identity
// provider's amr claim into it; record a federated sign-in as one
// application-defined Federated method.
func (p Policy) Satisfies(methods []Method, r Requirement) bool {
	var first, possession, webauthn, uv, phishingResistant bool
	for _, m := range methods {
		if m == MFA {
			uv = true
			continue
		}
		f, ok := p.Factors[m]
		if !ok {
			continue
		}
		switch f.Class {
		case Knowledge, Federated:
			first = true
		case Possession:
			possession = true
		default:
			continue
		}
		if (m == HWK || m == SWK) && f.Class == Possession {
			webauthn = true
		}
		if f.PhishingResistant {
			phishingResistant = true
		}
	}
	anyF := first || possession
	multi := (first && possession) || (webauthn && uv)
	switch r {
	case AnyFactor:
		return anyF
	case MultiFactor:
		return multi
	case PhishingResistant:
		return multi && phishingResistant
	default:
		return false
	}
}

// Fresh reports whether authTime is recent enough: at most within before now.
// A zero authTime or one after now is never fresh. Freshness answers "recent
// enough for a settings change" and says nothing about strength.
func Fresh(authTime time.Time, within time.Duration, now time.Time) bool {
	if authTime.IsZero() || authTime.After(now) {
		return false
	}
	return now.Sub(authTime) <= within
}
