## Why

Cnert only makes RSA keys and only signs with SHA-256, so a test suite
that needs an Ed25519 leaf, an EC intermediate or a SHA-512
signature has to drop down to raw `cryptography` and build the
fixture by hand. That happened three times while building the
certificate-hygiene audit in tlscertmon, which is exactly the job
cnert exists to spare people.

The two halves ship together because they are entangled: Ed25519 and
Ed448 refuse a hash algorithm, so widening the key type without also
making the hash a parameter produces keys that cannot be signed.

## What Changes

- `build_private_key()` gains a keyword `algorithm` selecting RSA
  (default), an EC curve, Ed25519 or Ed448. `key_size` and
  `public_exponent` stay, and apply to RSA only.
- The RSA-only annotations on `Cert`, `CSR`, `CA` and `_CertBuilder`
  widen to `cryptography`'s issuer/public key unions, so a
  caller-supplied non-RSA key type-checks.
- `Cert`, `CSR` and `CA.issue_cert()` gain a keyword
  `signature_hash`. It defaults to SHA-256 and accepts `None`,
  which Edwards keys require. Passing a hash with an Edwards key, or
  `None` with any other key type, raises `ValueError`. So does
  SHA-1 or MD5: `cryptography` refuses both for signatures, and
  cnert says so rather than letting `UnsupportedAlgorithm` through.
  The name is
  deliberately not `algorithm`: that word already means the key
  algorithm on `build_private_key()`.
- Signing an Edwards key defaults the hash to `None` automatically, so
  the common case needs no extra argument.
- Not breaking: every existing call keeps its current behaviour and
  its current return types. RSA stays the default everywhere.

## Capabilities

### New Capabilities

- `private-keys`: what key material cnert generates and accepts —
  algorithms, RSA sizing parameters, and the PEM/PKCS accessors that
  expose a key.
- `certificate-signing`: how a certificate or CSR is signed — which
  signing key is used, and how the signature hash is chosen and
  validated against the key type.

### Modified Capabilities

None. There is no spec baseline yet; these are the first two
capabilities.

## Impact

- `src/cnert/__init__.py`: `build_private_key`,
  `_CertBuilder.sign`, `Cert.__init__`, `Cert._build_certificate`,
  `Cert.public_key`, `CSR.__init__`, `CSR._gen_csr`,
  `CSR.public_key`, `CA.__init__`, `CA.issue_cert`.
- Public API: additive, keyword-only. Widened annotations mean a
  caller who annotated against `rsa.RSAPrivateKey` still type-checks;
  a caller who reads `Cert.private_key` now gets a union, which can
  surface as a new type-checker error downstream.
- Depends on `cryptography` asymmetric APIs available well before the
  current `>=50.0.1` floor: `ec.generate_private_key`,
  `ed25519.Ed25519PrivateKey`, `ed448.Ed448PrivateKey`, and the
  `CertificateIssuerPrivateKeyTypes` / `CertificatePublicKeyTypes`
  unions. No floor bump needed.
- Tests and the mkdocstrings API page grow with the new parameters.
