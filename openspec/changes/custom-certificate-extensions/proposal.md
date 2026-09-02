## Why

Cnert adds a fixed set of X.509 extensions: basic constraints, key
usage, extended key usage, subject alternative name, subject key
identifier and authority key identifier. Anything it has not modelled
is unreachable. A test that needs an OCSP must-staple certificate, a
certificate policy, a CRL distribution point or a name constraint has
to abandon cnert and drive `cryptography`'s builder directly, which
means rebuilding the whole chain by hand for one extra extension.

## What Changes

- `Cert`, `CA` and `CA.issue_cert()` gain a keyword `extensions`,
  a sequence of `(ExtensionType, critical)` pairs appended after the
  built-in set.
- `CSR` gains the same keyword, applied to the request's extensions.
- Supplying an extension that cnert already adds replaces cnert's
  version rather than producing a certificate with two copies, which
  is invalid. This makes the keyword an override hatch as well as an
  addition hatch.
- Not breaking: the keyword defaults to empty and the built-in
  extension set is unchanged when it is not used.

## Capabilities

### New Capabilities

- `certificate-extensions`: which X.509 extensions cnert puts on a
  certificate or request by default, and how a caller adds or
  overrides one.

### Modified Capabilities

None. The built-in extension behaviour is being written down for the
first time as part of this change.

## Impact

- `src/cnert/__init__.py`: `_CertBuilder.build`, the private
  `_add_*_extension` helpers, `Cert.__init__`,
  `Cert._build_certificate`, `CSR.__init__`, `CSR._gen_csr`,
  `CA.__init__`, `CA.issue_cert`.
- Public API: additive and keyword-only. The pair type is
  `tuple[x509.ExtensionType, bool]`, so a caller does import
  `cryptography.x509` to name an extension. That is unavoidable: the
  point of the hatch is extensions cnert does not model.
- Depends only on `x509.ExtensionType` and `x509.Extension`, both
  long-standing. No `cryptography` floor bump.
- Independent of the key-type and signature-hash work; the two can
  land in either order.
