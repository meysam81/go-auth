# go-auth v1

v1 (`github.com/meysam81/go-auth`) is in maintenance: security fixes only, for
twelve months from `v2.0.0` (`SECURITY.md`). New work goes to v2, on the `v2`
branch until `v2.0.0`.

- Never change an exported signature, remove a symbol or change a field's type:
  a v1.x fix keeps every consumer compiling. A behaviour change that closes a
  vulnerability is a `fix:` and is listed for consumers in
  `docs/security-hardening.md`, where every new finding is registered.
- Every fix ships a test that fails when the fix is reverted, named for the
  attack.
- Never name a consuming product in code, docs, commits or pull requests.
