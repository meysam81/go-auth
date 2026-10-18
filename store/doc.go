// Package store defines the single-use [FlowStore] and the error sentinels
// shared by every package that persists state.
//
// Durable credentials the application administers are typed: each package
// declares the narrow interface it calls and the application maps it onto its
// own tables. Short-lived ceremony state only the library reads is opaque: it
// is held as a [Flow] in one FlowStore, whose payload the application never
// interprets.
//
// Every store keeps a [time.Time] as an instant to at least the microsecond,
// the finest PostgreSQL and MySQL keep: it may truncate or round below that,
// and return the instant in any location. A column that keeps seconds, or the
// wall clock without its offset, does not meet the contract.
//
// The library never deletes a flow: [FlowStore.Take] only refuses consumed
// and expired ones, so the application purges them on a schedule. It also
// rate-limits every unauthenticated Begin, which writes a flow per call.
package store
