## Why

There is no way to build a certificate without cnert's built-in
extensions. `extensions=[]` does not suppress them: a leaf always
carries subject key identifier, basic constraints, key usage,
extended key usage and, when given names, a subject alternative name.

That leaves a whole class of test unreachable. A parser has to prove
that an absent extension reads as `None`, and it cannot do that
against a certificate that always has every extension. tlscertmon
reported that its raw `CertificateBuilder` fixtures cannot leave its
conftest for exactly this reason, even after taking every other
0.11.0 feature.

The extensions hatch adds and overrides. It cannot subtract.

## What Changes

- `Cert`, `CSR`, `CA`, `CA.issue_intermediate()` and
  `CA.issue_cert()` gain a keyword `builtin_extensions`, defaulting
  to `True`.
- With `builtin_extensions=False`, only caller-supplied extensions
  are added. Everything cnert would add by itself is suppressed,
  including the subject alternative name built from `sans`.
- Suppression and the `extensions` hatch compose: a bare certificate
  carrying exactly one chosen extension is one call.
- Not breaking: the default reproduces current output exactly.

## Capabilities

### Modified Capabilities

- `certificate-extensions`: the built-in set becomes suppressible,
  so the capability now describes when it is applied rather than
  asserting it always is.

## Impact

- `src/cnert/__init__.py`: `_CertBuilder.build`, `Cert.__init__`,
  `Cert._build_certificate`, `CSR.__init__`, `CSR._gen_csr`,
  `CA.__init__`, `CA.issue_intermediate`, `CA.issue_cert`.
- Public API: additive and keyword-only.
- A certificate built this way is deliberately not a valid
  certificate for any real use: an authority without basic
  constraints is not an authority. That is the point, and it is
  documented rather than validated.
- No new dependency and no `cryptography` floor bump.
