// Package sqlitestore is a reference implementation of [store.FlowStore],
// [webauthn.CredentialStore] and [webauthn.HandleStore] on SQLite, through
// database/sql and the pure-Go modernc.org/sqlite driver. Its tests run the
// authtest conformance suites against it.
//
// It is an example to copy and adapt, not a supported package: it lives in
// its own module so the library's dependencies do not grow, and its API may
// change in any release.
//
//	db, err := sqlitestore.Open(ctx, "auth.db")
//	// ...
//	err = sqlitestore.Migrate(ctx, db) // or apply schema.sql with your migration tool
//	flows, err := sqlitestore.NewFlowStore(sqlitestore.Config{DB: db})
//	creds, err := sqlitestore.NewWebAuthnStore(sqlitestore.Config{DB: db}) // both webauthn stores
//
// Take marks a flow used and leaves the row; delete consumed and expired rows
// on a schedule of your own, for example
// DELETE FROM flows WHERE used_at IS NOT NULL OR expires_at <= ? with
// time.Now().UnixMicro() as the argument. Times are INTEGER Unix microseconds:
// bound as a time.Time the argument is TEXT, every integer sorts below text in
// SQLite, and the statement deletes every flow, live ones included.
//
// # Porting it to another database
//
// Keep these decisions. The conformance suites check the behaviour they
// produce wherever the interfaces can see it; the time precision, and which
// conflicts with an application's own indexes are [store.ErrDuplicate], are
// pinned by this package's own tests, so port those tests with the code:
//
//   - Every state change is one conditional statement, judged by its
//     affected-row count or its RETURNING row: Take is UPDATE ... WHERE
//     used_at IS NULL AND expires_at > now, RecordAssertion is UPDATE ...
//     WHERE sign_count = the previous count. Never a read followed by a
//     write: two concurrent callers both pass the read. On MySQL, connect
//     with clientFoundRows=true, or an update that changes no column (a
//     counter that stays 0 and a last-used time equal to the stored one)
//     reports no row.
//   - The credential ID has a unique index of its own, not one on (subject,
//     credential ID): an ID belongs to at most one subject. A violation of
//     that index, and only that one, is [store.ErrDuplicate]; tell it apart
//     by error code or constraint name, never by the message.
//   - Times are stored as instants in UTC at a fixed precision: [TimePrecision],
//     the finest PostgreSQL and MySQL keep. A column that keeps the wall clock
//     and drops the offset moves every instant written from another zone.
//   - Byte columns are binary (BLOB, bytea, VARBINARY): compared byte for
//     byte, never as text under a collation, and wide enough for a 1023-byte
//     credential ID.
package sqlitestore
