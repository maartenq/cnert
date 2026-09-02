# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

Add entries under [Unreleased] as you work; `task release` stamps them
into a dated version section.

## [Unreleased]

### Added

- `build_private_key()` takes an `algorithm` argument: `rsa` (the
  default), `ed25519`, `ed448`, or one of the curve names
  `secp256r1`, `secp384r1`, `secp521r1`. The full tuple is exported as
  `cnert.KEY_ALGORITHMS`. `key_size` and `public_exponent` stay
  RSA-only and now raise for other algorithms instead of being
  ignored.
- `Cert`, `CSR`, `CA` and `CA.issue_cert()` take a `signature_hash`
  argument. It defaults to SHA-256, and to `None` for an Edwards key,
  which signs without a separate hash. Passing a hash with an Edwards
  key, `None` with any other key type, or SHA-1 or MD5 with anything
  raises `ValueError`. SHA-1 and MD5 cannot sign an X.509 certificate
  at all; cnert says so rather than letting the underlying
  `UnsupportedAlgorithm` through.
- `Cert`, `CSR`, `CA` and `CA.issue_cert()` take an `extensions`
  sequence of `(extension, critical)` pairs, for extensions cnert does
  not model, such as TLS Feature (OCSP must-staple), certificate
  policies or name constraints. A supplied extension that collides
  with a built-in one replaces it, so this is also the way to override
  key usage or basic constraints.

### Changed

- `_Cert` is renamed to `Cert`: it was always returned by the public
  `CA.issue_cert()`, so consumers had to reference a private name to
  annotate their code. `cnert._Cert` remains as a deprecated alias.
- `NameAttrs` is now hashable (it is frozen), and comparing it to a
  non-`NameAttrs` object returns `NotImplemented` instead of raising
  `AttributeError`.
- Better annotations throughout: typed `NameAttrs(**kwargs: str)`,
  class-level attribute annotations on `Cert`/`CSR`/`CA`, `@override`
  markers, and a `[tool.basedpyright]` section so editor LSPs check
  clean. `Freezer` no longer mutates a shared `__slots__` list (it had
  no slotting effect and grew per instantiation).
- Minimum dependencies raised to `cryptography>=50.0.1` and
  `idna>=3.19`, ahead of widening key-type support.
- Key annotations widen from `rsa.RSAPrivateKey` and
  `rsa.RSAPublicKey` to `cryptography`'s issuer key unions, so
  non-RSA keys type-check. Runtime behaviour is unchanged, but code
  that reads `Cert.private_key` or `Cert.public_key` and passes it
  somewhere RSA-specific may see a new type-checker error.
- `private_key_pem_PKCS1` raises `ValueError` for a non-RSA key,
  naming `private_key_pem_PKCS8` as the alternative, instead of
  failing inside `cryptography`.

### Fixed

- `NameAttrs.allowed_keys()` no longer depends on
  `cls.__dict__["__annotations__"]`, which breaks under PEP 649 lazy
  annotations once `from __future__ import annotations` is dropped on
  Python >= 3.14.

## [0.10.3] - 2026-07-17

### Added

- Internal only: a `CHANGELOG.md`, and a release flow that stamps
  `[Unreleased]` notes into a dated section within the release commit.

## [0.10.2] - 2026-07-17

### Changed

- Internal only: no functional changes to the library. Release tooling
  now builds with `uv` instead of Poetry; added a documented one-command
  release flow (`task release`) and `AGENTS.md`; set the Ruff
  `target-version` to `py312`.

### Fixed

- `git:check` task always failed on a clean tree due to a shell
  precedence bug.

## [0.10.1] - 2026-07-17

### Changed

- `__version__` is now read from the installed package metadata instead
  of a hardcoded string, so it always matches the released version.

### Removed

- Dropped the no-op `backend=default_backend()` arguments (ignored by
  `cryptography` since 3.1) and the `default_backend` import.

## [0.10.0] - 2026-07-17

### Added

- Support for Python 3.14.

[Unreleased]: https://github.com/maartenq/cnert/compare/0.10.3...HEAD
[0.10.3]: https://github.com/maartenq/cnert/releases/tag/0.10.3
[0.10.2]: https://github.com/maartenq/cnert/releases/tag/0.10.2
[0.10.1]: https://github.com/maartenq/cnert/releases/tag/0.10.1
[0.10.0]: https://github.com/maartenq/cnert/releases/tag/0.10.0
