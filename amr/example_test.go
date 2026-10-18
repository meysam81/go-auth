package amr_test

import (
	"fmt"
	"time"

	"github.com/meysam81/go-auth/v2/amr"
)

func ExamplePolicy_Satisfies() {
	policy := amr.Standard()

	passwordOnly := []amr.Method{amr.PWD}
	passwordAndOTP := []amr.Method{amr.PWD, amr.OTP}
	passkey := []amr.Method{amr.SWK, amr.MFA} // one assertion that verified the user

	fmt.Println("password, any factor:", policy.Satisfies(passwordOnly, amr.AnyFactor))
	fmt.Println("password, multi-factor:", policy.Satisfies(passwordOnly, amr.MultiFactor))
	fmt.Println("password + otp, multi-factor:", policy.Satisfies(passwordAndOTP, amr.MultiFactor))
	fmt.Println("password + otp, phishing-resistant:", policy.Satisfies(passwordAndOTP, amr.PhishingResistant))
	fmt.Println("passkey, phishing-resistant:", policy.Satisfies(passkey, amr.PhishingResistant))

	// A method the policy does not classify counts for nothing.
	fmt.Println("unknown method:", policy.Satisfies([]amr.Method{"sms"}, amr.AnyFactor))
	// Output:
	// password, any factor: true
	// password, multi-factor: false
	// password + otp, multi-factor: true
	// password + otp, phishing-resistant: false
	// passkey, phishing-resistant: true
	// unknown method: false
}

func ExampleFresh() {
	now := time.Date(2026, time.January, 2, 12, 0, 0, 0, time.UTC)
	within := 5 * time.Minute

	recent := now.Add(-2 * time.Minute)
	stale := now.Add(-30 * time.Minute)

	fmt.Println("2 minutes ago:", amr.Fresh(recent, within, now))
	fmt.Println("30 minutes ago:", amr.Fresh(stale, within, now))
	fmt.Println("never:", amr.Fresh(time.Time{}, within, now))
	// Output:
	// 2 minutes ago: true
	// 30 minutes ago: false
	// never: false
}
