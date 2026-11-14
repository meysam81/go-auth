// Package hydra is a client for the Ory Hydra admin API: it reads and answers
// login and consent requests, revokes consent and login sessions, and lists
// and deletes OAuth 2.0 clients.
//
// Hydra is the authorization server; the application owns the user and every
// identity decision. The client carries the application's answer to Hydra
// and never chooses a subject, a scope or an answer itself.
//
// A login or consent challenge Hydra does not know (404) or has expired
// (Hydra v26 answers 401 with the error request_unauthorized) matches
// [ErrInvalidChallenge], as does one it reports as answered or expired with 409
// or 410: answer the browser alike in every case. Answering a challenge twice
// before the browser follows redirect_to is not an error: Hydra overwrites the
// first answer and returns a redirect. Every other failure, any other 401
// included, matches no sentinel and is an infrastructure failure. An error's
// text is for logs only.
//
// The admin API has no authentication of its own: reach it only over a
// network the application controls. Requests go through the *http.Client the
// application supplies, which must carry a Timeout; the client never follows
// a redirect and never reads more than 1 MiB of an answer.
package hydra
