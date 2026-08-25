# Changelog

## [1.1.3](https://github.com/meysam81/go-auth/compare/v1.1.2...v1.1.3) (2026-08-25)


### Bug Fixes

* **basic:** MFA gate fails open when the Authenticator has no TOTP manager ([#55](https://github.com/meysam81/go-auth/issues/55)) ([d68aa2f](https://github.com/meysam81/go-auth/commit/d68aa2f6e6cc4a42b4a0c55ff505d4c0f846305f))

## [1.1.2](https://github.com/meysam81/go-auth/compare/v1.1.1...v1.1.2) (2026-08-24)


### Bug Fixes

* **deps:** update module github.com/coreos/go-oidc/v3 to v3.17.0 ([#24](https://github.com/meysam81/go-auth/issues/24)) ([c4d2e56](https://github.com/meysam81/go-auth/commit/c4d2e56cafed5028362cde7bb0a59a484088d97f))
* **deps:** update module golang.org/x/crypto to v0.45.0 [security] ([#22](https://github.com/meysam81/go-auth/issues/22)) ([3841f3d](https://github.com/meysam81/go-auth/commit/3841f3db4c9f078c765b47e2db7bbe0dfb81ac23))
* **deps:** update module golang.org/x/oauth2 to v0.34.0 ([#30](https://github.com/meysam81/go-auth/issues/30)) ([ae73ef9](https://github.com/meysam81/go-auth/commit/ae73ef9ec86bfa48e50d6019b9112e406e6830ee))
* **security:** harden the library against 32 audit findings ([#49](https://github.com/meysam81/go-auth/issues/49)) ([095e65f](https://github.com/meysam81/go-auth/commit/095e65fe91847b7aa2ee64ff35fe886b3c3f91ab))


### Build & Dependencies

* **deps:** pin dependencies ([#48](https://github.com/meysam81/go-auth/issues/48)) ([88acac5](https://github.com/meysam81/go-auth/commit/88acac5d5101bdabd1ce2042612ccea6048de9b3))
* **deps:** update actions/cache action to v6 ([#44](https://github.com/meysam81/go-auth/issues/44)) ([b309b68](https://github.com/meysam81/go-auth/commit/b309b68f1fe58026ed9a42f2d51c51f839dac95a))
* **deps:** update actions/checkout action to v7 ([#43](https://github.com/meysam81/go-auth/issues/43)) ([fbbdec4](https://github.com/meysam81/go-auth/commit/fbbdec48b8a1d9c9cb48e0bd3004214c40876d8d))
* **deps:** update actions/setup-go action to v7 ([#45](https://github.com/meysam81/go-auth/issues/45)) ([6126ddd](https://github.com/meysam81/go-auth/commit/6126ddd58e0427282f505e85ec47b58100fdc64d))
* **deps:** update codecov/codecov-action action to v7 ([#42](https://github.com/meysam81/go-auth/issues/42)) ([2b05b2f](https://github.com/meysam81/go-auth/commit/2b05b2fcf8b9df7d1d5ee9a6ce4232004d830bda))
* **deps:** update googleapis/release-please-action action to v5 ([#41](https://github.com/meysam81/go-auth/issues/41)) ([faea11a](https://github.com/meysam81/go-auth/commit/faea11ae5c6c3649da791a21a65cd9bc4a74f369))


### Chores

* **deps:** go mod tidy ([1bbb3d1](https://github.com/meysam81/go-auth/commit/1bbb3d1e18d4baf46cb901889ab1470c46a69c1c))
* **deps:** pre-commit autoupdate ([eb8bf11](https://github.com/meysam81/go-auth/commit/eb8bf116deb98c932d097e0b3ce0a94f37b4bd1a))
* **deps:** update actions/checkout action to v6 ([#23](https://github.com/meysam81/go-auth/issues/23)) ([d4d74cb](https://github.com/meysam81/go-auth/commit/d4d74cb80e04ff52a490881eb9b4e04125715781))
* **deps:** upgrade all dependencies at once ([#54](https://github.com/meysam81/go-auth/issues/54)) ([04b479f](https://github.com/meysam81/go-auth/commit/04b479fdd122ae811a1629343a3d2de00d89de0e))
* **docs:** add additional badges ([fed2606](https://github.com/meysam81/go-auth/commit/fed2606c25b97808ed2867666b98ae5b2f543bdd))
* **renovate:** extend my own base ([1241f3e](https://github.com/meysam81/go-auth/commit/1241f3e9663baaf9255adc60052338816f14dbae))


### CI

* **merge-queue:** trigger on merge_group and document the queue setup ([#51](https://github.com/meysam81/go-auth/issues/51)) ([c2d944c](https://github.com/meysam81/go-auth/commit/c2d944c82aa85d02e228891d52bacfa373ca21f7))
* **release:** drive release-please from a manifest config ([#53](https://github.com/meysam81/go-auth/issues/53)) ([2e0c48c](https://github.com/meysam81/go-auth/commit/2e0c48c765480947a7ffd27a018a3c0c53333394))


### Documentation

* add comprehensive OIDC server implementation research ([#31](https://github.com/meysam81/go-auth/issues/31)) ([05a9682](https://github.com/meysam81/go-auth/commit/05a96829f3053b45d8c0f40dfd2cb1a0dd97e455))
* add comprehensive product roadmap ([74d481a](https://github.com/meysam81/go-auth/commit/74d481af66f4855197438bc80178250cfa1844ed))
* update CLAUDE.md with current release version and complete example ([#26](https://github.com/meysam81/go-auth/issues/26)) ([6966ac4](https://github.com/meysam81/go-auth/commit/6966ac4178d557a1603f2cde5c495d994763e7d4))

## [1.1.1](https://github.com/meysam81/go-auth/compare/v1.1.0...v1.1.1) (2025-11-19)


### Bug Fixes

* add funding ([7a71cb3](https://github.com/meysam81/go-auth/commit/7a71cb327e6d07d8fa8cea470f9612a2cf32982d))
* **deps:** update go mods ([44234b3](https://github.com/meysam81/go-auth/commit/44234b3582be5c91e20f1b9b755bb4c1b04a82d1))
* **dev:** add prettier to pre-commit ([2779c5d](https://github.com/meysam81/go-auth/commit/2779c5d1194632333170cb9f5bd2ec2cb4168af7))
* **docs:** update roadmap ([7bff778](https://github.com/meysam81/go-auth/commit/7bff7788197449ff31ce31b35c5c0332d62a127e))
* remove lowercase claude ([2c97b67](https://github.com/meysam81/go-auth/commit/2c97b67da15e9e112162518b91ee0d8681ac255f))

## [1.1.0](https://github.com/meysam81/go-auth/compare/v1.0.1...v1.1.0) (2025-11-19)

### Features

- **docs:** Improve README documentation and setup instructions ([#18](https://github.com/meysam81/go-auth/issues/18)) ([08c36ec](https://github.com/meysam81/go-auth/commit/08c36ec3d3a694c0d4ef37c389ddb397e35dbb8e))
- Implement authentication flow helpers and TOTP ([#15](https://github.com/meysam81/go-auth/issues/15)) ([eb07702](https://github.com/meysam81/go-auth/commit/eb077029e83a1c115c0efc98ca0a79a0ac7b079e))

## [1.0.1](https://github.com/meysam81/go-auth/compare/v1.0.0...v1.0.1) (2025-11-15)

### Bug Fixes

- **deps:** update module github.com/go-webauthn/webauthn to v0.15.0 ([#6](https://github.com/meysam81/go-auth/issues/6)) ([8961440](https://github.com/meysam81/go-auth/commit/89614406f76b022e140a42c886ab907fa31cd1a2))
- **deps:** update module golang.org/x/crypto to v0.44.0 ([#7](https://github.com/meysam81/go-auth/issues/7)) ([8a5a66c](https://github.com/meysam81/go-auth/commit/8a5a66c162ed7cc32fb8373c0fb35d221e59f826))
- **deps:** update module golang.org/x/oauth2 to v0.33.0 ([b95f7d3](https://github.com/meysam81/go-auth/commit/b95f7d35059a67722beae56c8853e5ada2f589a9))

## 1.0.0 (2025-11-15)

### Features

- add comprehensive audit logging interface ([9137904](https://github.com/meysam81/go-auth/commit/9137904c8c5b62af40678b3147d2c9ad02fb1dd0))
- add reusable Go authentication library ([#1](https://github.com/meysam81/go-auth/issues/1)) ([720cc10](https://github.com/meysam81/go-auth/commit/720cc10be35922609919c0850a5b3d771de143e7))

### Bug Fixes

- resolve all golangci-lint issues ([a6d0d68](https://github.com/meysam81/go-auth/commit/a6d0d686bbea420b1411a74f5e9a20e17ce0344e))
