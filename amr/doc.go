// Package amr is the authentication-methods vocabulary of RFC 8176 and the
// policy that decides whether a set of methods satisfies a requirement.
//
// A session records which methods proved it. The library classifies that set;
// the application decides which classifications may hold a session. The
// verdict is derived from the methods every time it is needed and is never
// stored.
//
// The policy fails closed: a method the [Policy] does not classify counts for
// nothing, and so does an undefined [Requirement]. Unknown is never a pass.
//
// Freshness is a separate question from strength; see [Fresh].
package amr
