## cnert

### Class cnert.CA

::: cnert.CA

### Class cnert.NameAttrs

Instances are frozen and hashable; comparing against a non-`NameAttrs`
object returns `False` instead of raising.

A value may be a sequence, which emits one attribute per value in the
order given. That is how a distinguished name repeats an attribute
type, which a lossless DN parse has to be tested against:

```python
import cnert

subject = cnert.NameAttrs(
    COMMON_NAME="example.com", ORGANIZATIONAL_UNIT_NAME=["OU-A", "OU-B"]
)
```

Each value becomes its own relative distinguished name. The
plus-joined `OU=A+OU=B` form, one relative distinguished name holding
both, is not reachable this way. A multi-valued attribute reads back
as a tuple. Note that `rfc4514_string()` prints most-specific first,
so it renders the name above with `OU-B` before `OU-A`; the attribute
order is still the one given.

Anything that is not a `NameAttrs` passed as `subject_attrs` or
`issuer_attrs` raises `TypeError`.

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
`Cert`, `CSR`, `CA` and `CA.issue_cert()`. It takes a name from
`cnert.SIGNATURE_HASHES` or a `cryptography` hash object:

```python
import cnert

cert = cnert.CA().issue_cert("example.com", signature_hash="sha512")
```

It defaults to SHA-256, and to `None` for an Edwards key, which signs
without a separate hash. SHA-1 and MD5 are refused by either form:
they cannot sign an X.509 certificate.

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

To subtract instead, pass `builtin_extensions=False`. Only the
supplied pairs are then added, subject alternative names included, so
a bare certificate carrying exactly one chosen extension is one call:

```python
import cnert

bare = cnert.CA().issue_cert("example.com", builtin_extensions=False)
```

A certificate built that way is not valid for any real use, and an
authority built that way is not a usable authority. That is the point.
It is how a parser test proves an absent extension reads as absent.

### Supplying keys

`CA()`, `CA.issue_intermediate()` and `CA.issue_cert()` take a
`private_key`, which is how an undersized key or an unusual public
exponent becomes reachable:

```python
import cnert

ca = cnert.CA(private_key=cnert.build_private_key(key_size=1024))
cert = ca.issue_cert(
    "example.com", private_key=cnert.build_private_key(public_exponent=3)
)
```

A supplied key is the certificate's subject key only. The signature
always comes from the issuing CA's key. A `csr` already carries a key,
so passing both a `csr` and a `private_key` raises `ValueError`.
Passing the same key at several levels is allowed, and is how a
key-reuse fixture is built.

### Function idna_encode

::: cnert.idna_encode

### Function identity_string_to_x509

::: cnert.identity_string_to_x509
