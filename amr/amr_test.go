package amr_test

import (
	"slices"
	"testing"
	"time"

	"github.com/meysam81/go-auth/v2/amr"
)

var app = amr.Standard().
	With("sso", amr.Factor{Class: amr.Federated}).
	With("rc", amr.Factor{Class: amr.Possession}).
	With("email", amr.Factor{Class: amr.Possession})

func TestSatisfies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		set          []amr.Method
		any, mf, phr bool
	}{
		{"password only", []amr.Method{"pwd"}, true, false, false},
		{"password and totp", []amr.Method{"pwd", "otp"}, true, true, false},
		{"user-verified synced passkey", []amr.Method{"swk", "mfa"}, true, true, true},
		{"device-bound key without UV", []amr.Method{"hwk"}, true, false, false},
		{"password and security key", []amr.Method{"pwd", "hwk"}, true, true, true},
		{"mfa alone", []amr.Method{"mfa"}, false, false, false},
		{"mfa beside otp is not webauthn", []amr.Method{"otp", "mfa"}, true, false, false},
		{"empty", nil, false, false, false},
		{"unknown value", []amr.Method{"xyz"}, false, false, false},
		{"sso alone", []amr.Method{"sso"}, true, false, false},
		{"sso and totp", []amr.Method{"sso", "otp"}, true, true, false},
		{"password and sso are two first factors", []amr.Method{"pwd", "sso"}, true, false, false},
		{"recovery path", []amr.Method{"pwd", "rc", "email", "otp"}, true, true, false},
		{"sso and passkey", []amr.Method{"sso", "swk"}, true, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := app.Satisfies(tt.set, amr.AnyFactor); got != tt.any {
				t.Errorf("AnyFactor = %v, want %v", got, tt.any)
			}
			if got := app.Satisfies(tt.set, amr.MultiFactor); got != tt.mf {
				t.Errorf("MultiFactor = %v, want %v", got, tt.mf)
			}
			if got := app.Satisfies(tt.set, amr.PhishingResistant); got != tt.phr {
				t.Errorf("PhishingResistant = %v, want %v", got, tt.phr)
			}
		})
	}
}

func TestSatisfies_UndefinedRequirementFailsClosed(t *testing.T) {
	t.Parallel()
	sets := [][]amr.Method{{"pwd", "hwk"}, {"swk", "mfa"}, {"pwd"}, nil}
	for _, r := range []amr.Requirement{0, 4, 99} {
		for _, set := range sets {
			if app.Satisfies(set, r) {
				t.Errorf("Satisfies(%v, %d) = true, want false", set, r)
			}
		}
	}
}

func TestMFAIsNeverAFactor(t *testing.T) {
	t.Parallel()
	if _, ok := amr.Standard().Factors[amr.MFA]; ok {
		t.Fatal("Standard classifies mfa")
	}
	p := amr.Standard().With(amr.MFA, amr.Factor{Class: amr.Possession, PhishingResistant: true})
	if _, ok := p.Factors[amr.MFA]; ok {
		t.Error("With classified mfa")
	}
	// A hand-built policy that classifies mfa still does not count it.
	raw := amr.Policy{Factors: map[amr.Method]amr.Factor{
		amr.MFA: {Class: amr.Possession, PhishingResistant: true},
		amr.PWD: {Class: amr.Knowledge},
	}}
	for _, pol := range []amr.Policy{p, raw} {
		for _, r := range []amr.Requirement{amr.AnyFactor, amr.MultiFactor, amr.PhishingResistant} {
			if pol.Satisfies([]amr.Method{"mfa"}, r) {
				t.Errorf("mfa alone satisfied %d", r)
			}
		}
		if pol.Satisfies([]amr.Method{"pwd", "mfa"}, amr.MultiFactor) {
			t.Error("pwd and mfa counted as multi-factor")
		}
	}
}

func TestWith_ZeroPolicy(t *testing.T) {
	t.Parallel()
	p := amr.Policy{}.With("pwd", amr.Factor{Class: amr.Knowledge})
	if !p.Satisfies([]amr.Method{"pwd"}, amr.AnyFactor) {
		t.Error("With on a zero Policy lost the method")
	}
}

func TestSatisfies_ExhaustiveImplications(t *testing.T) {
	t.Parallel()
	all := []amr.Method{"pwd", "otp", "hwk", "swk", "mfa", "sso", "rc"}
	reqs := []amr.Requirement{amr.AnyFactor, amr.MultiFactor, amr.PhishingResistant}
	for mask := range 1 << len(all) {
		var set []amr.Method
		for i, m := range all {
			if mask&(1<<i) != 0 {
				set = append(set, m)
			}
		}
		verdict := func(s []amr.Method) [3]bool {
			var v [3]bool
			for i, r := range reqs {
				v[i] = app.Satisfies(s, r)
			}
			return v
		}
		v := verdict(set)
		if v[2] && !v[1] {
			t.Errorf("%v: PhishingResistant without MultiFactor", set)
		}
		if v[1] && !v[0] {
			t.Errorf("%v: MultiFactor without AnyFactor", set)
		}
		rev := slices.Clone(set)
		slices.Reverse(rev)
		dup := slices.Concat(set, set)
		if verdict(rev) != v || verdict(dup) != v {
			t.Errorf("%v: verdict depends on order or duplicates", set)
		}
	}
}

func TestStandard_ReturnsIndependentCopies(t *testing.T) {
	t.Parallel()
	a := amr.Standard()
	a.Factors["pwd"] = amr.Factor{Class: amr.Unknown}
	delete(a.Factors, "otp")
	b := amr.Standard()
	if b.Factors["pwd"].Class != amr.Knowledge || b.Factors["otp"].Class != amr.Possession {
		t.Error("mutating one Standard() leaked into the next")
	}

	base := amr.Standard()
	n := len(base.Factors)
	derived := base.With("sso", amr.Factor{Class: amr.Federated})
	if len(base.Factors) != n {
		t.Error("With mutated its receiver")
	}
	if _, ok := base.Factors["sso"]; ok {
		t.Error("With leaked into its receiver")
	}
	if derived.Factors["sso"].Class != amr.Federated {
		t.Error("With did not add the method")
	}
}

func TestFresh(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	within := 5 * time.Minute
	tests := []struct {
		name string
		auth time.Time
		want bool
	}{
		{"zero authTime", time.Time{}, false},
		{"authTime after now", now.Add(time.Nanosecond), false},
		{"authTime equals now", now, true},
		{"exactly within", now.Add(-within), true},
		{"within plus 1ns", now.Add(-within - time.Nanosecond), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := amr.Fresh(tt.auth, within, now); got != tt.want {
				t.Errorf("Fresh = %v, want %v", got, tt.want)
			}
		})
	}
}
