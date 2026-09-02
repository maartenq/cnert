## Context

See proposal.md - Why. The constraints that shape the approach:

- One module, plain keyword arguments, no new runtime dependency.
  Cnert's whole appeal is that a fixture is one call.
- `Cert`, `CSR` and `CA` are published API. Their annotations are
  read by downstream type checkers, so widening them is itself an
  observable change.
- `_CertBuilder.sign()` and `CSR._gen_csr()` are the only two places
  that hand a key and a hash to the cryptography library. Everything
  else is plumbing.

## Goals / Non-Goals

**Goals:**

- One obvious way to ask for a key of a given algorithm.
- The signing rules (Edwards takes no hash, everything else needs
  one) enforced by cnert with a readable error, not surfaced as a
  cryptography traceback.
- No behaviour change for any call that exists today.

**Non-Goals:**

- DSA, X25519 and X448. DSA is dead for TLS; the X-curves do key
  agreement, not signing, so they cannot sign a certificate.
- Encrypted private key output. Unrelated to key type.
- Choosing the hash per certificate in a chain automatically. The
  caller passes what it wants at each level.

## Decisions

### Algorithm is a string name, resolved by a module-level table

`build_private_key(algorithm="ed25519")`, `algorithm="secp384r1"`.
A module-level mapping of name to constructor covers RSA, Ed25519,
Ed448 and the three NIST curves (`secp256r1`, `secp384r1`,
`secp521r1`). An unknown name raises `ValueError` listing the keys of
that table.

Alternative considered: take cryptography objects, e.g.
`algorithm=ec.SECP384R1()`. Rejected because it forces every caller
to import from `cryptography.hazmat`, which is exactly the import
cnert exists to hide. The mapping is also the natural place to add a
curve later.

Alternative considered: a `StrEnum`. Rejected as a second exported
name to learn for no gain; a plain string is what a test fixture
reads best, and the error message enumerates the valid values.

### The hash parameter is `signature_hash`, not `algorithm`

`algorithm` already means the key algorithm on `build_private_key()`.
Reusing it for the hash would make `algorithm="ed25519"` and
`algorithm=hashes.SHA256()` two different things in the same API.

### An `_UNSET` sentinel distinguishes "not passed" from `None`

`None` is a meaningful value (Edwards keys need it), so it cannot
double as the default. A module-private sentinel is the default;
`_UNSET` resolves to `None` for Edwards keys and SHA-256 for
everything else.

Alternative considered: defaulting to SHA-256 and special-casing
Edwards keys inside the signer. Rejected because it silently ignores
an explicit `signature_hash=hashes.SHA256()` on an Edwards key, which
is a caller mistake worth reporting.

### The allowed hash set is cnert's own tuple

`cryptography` types the hash argument as a module-private union of
the SHA-2 and SHA-3 classes, so cnert cannot name it. A module-level
tuple of the same classes drives an `isinstance` check, and the
resolved hash is cast at the two `sign()` call sites.

Alternative considered: importing the private union. Rejected as a
dependency on a name that can move in any release.

### One helper validates the key and hash pair

`_signature_hash_for(private_key, signature_hash)` returns the hash
to use or raises. Both `_CertBuilder.sign()` and `CSR._gen_csr()`
call it, so the two paths cannot drift. Edwards detection is an
`isinstance` check against the two Edwards key classes.

### Annotations widen to the cryptography unions

Private keys become `CertificateIssuerPrivateKeyTypes`, public keys
become `CertificatePublicKeyTypes`. These are the unions the
cryptography library itself uses for the builder, so cnert's
annotations match what it actually passes through.

### PKCS#1 stays RSA-only and says so

`TraditionalOpenSSL` is meaningless for Edwards keys. The accessor
raises `ValueError` naming PKCS#8 as the alternative rather than
emitting something that is not a PKCS#1 document.

## Risks / Trade-offs

- **A downstream type checker breaks.** Reading `Cert.private_key`
  used to yield `rsa.RSAPrivateKey` and now yields a union, so code
  that passes it somewhere RSA-specific gets a new error. → Call it
  out in the changelog as a typing-only change; the runtime object is
  unchanged when the default is used. Consider it a minor bump.
- **The curve table is a curated subset.** Someone wanting
  `secp256k1` cannot get it. → The table is one line per curve, and
  the error message shows what exists.
- **Weak-signature fixtures stay out of reach.** `cryptography`
  refuses SHA-1 and MD5 for signatures outright, so a certificate
  carrying one cannot be built through its builder at all. → cnert
  refuses them itself with a message that says why, and a test
  needing such a fixture still has to hand-roll a PEM. Reaching them
  would mean assembling the certificate DER and signing the TBS bytes
  directly, which is a separate change and a new dependency.

## Migration Plan

None needed. Every addition is keyword-only with a default that
reproduces current behaviour. No release ordering constraint beyond
the usual bump-commit-tag.
