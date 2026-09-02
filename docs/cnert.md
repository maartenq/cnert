## cnert

### Class cnert.CA

::: cnert.CA

### Class cnert.NameAttrs

Instances are frozen and hashable; comparing against a non-`NameAttrs`
object returns `False` instead of raising.

::: cnert.NameAttrs

### Class cnert._CertBuilder

::: cnert._CertBuilder

### Class cnert.Cert

`Cert` was named `_Cert` through 0.10.x even though the public
`CA.issue_cert()` returned it; the old name remains as a deprecated
alias.

::: cnert.Cert

### Class cnert.CSR

::: cnert.CSR

### Function build_private_key

::: cnert.build_private_key

### Key algorithms

`cnert.KEY_ALGORITHMS` is the tuple of names `build_private_key`
accepts: `rsa` (the default), `ed25519`, `ed448`, and the curve names
`secp256r1`, `secp384r1` and `secp521r1`.

Signature hashes are chosen with the `signature_hash` argument on
`Cert`, `CSR`, `CA` and `CA.issue_cert()`. It defaults to SHA-256, and
to `None` for an Edwards key, which signs without a separate hash.
SHA-1 and MD5 are refused: they cannot sign an X.509 certificate.

### Extra extensions

`Cert`, `CSR`, `CA` and `CA.issue_cert()` take an `extensions`
sequence of `(extension, critical)` pairs, for anything cnert does not
model itself:

```python
from cryptography import x509

import cnert

must_staple = x509.TLSFeature([x509.TLSFeatureType.status_request])
cert = cnert.CA().issue_cert("example.com", extensions=[(must_staple, False)])
```

A supplied extension whose object identifier matches one cnert adds by
itself replaces cnert's version wholesale, keeping its position. That
makes the argument an override as well as an addition, and it is the
only way to change key usage or basic constraints.

### Function idna_encode

::: cnert.idna_encode

### Function identity_string_to_x509

::: cnert.identity_string_to_x509
