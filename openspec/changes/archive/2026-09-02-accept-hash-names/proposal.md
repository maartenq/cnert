## Why

`signature_hash="sha512"` crashes with `AttributeError: 'str' object
has no attribute 'name'`, thrown from inside the validator's own error
message. Any wrong-typed value dies there instead of producing the
clear `ValueError` cnert works hard to give everywhere else.

The root cause is an asymmetry this library introduced in the same
release: `build_private_key(algorithm="ed25519")` takes a string,
while `signature_hash` on the same call site takes an object. A
tester reaching for the string is following the API's own precedent.
Found by tlscertmon porting its fixtures to 0.11.0.dev0.

## What Changes

- `signature_hash` accepts a name as well as a hash object:
  `"sha256"`, `"sha384"`, `"sha512"`, the SHA-3 four, and `"sha224"`.
  Objects keep working unchanged.
- The usable names are exported as `cnert.SIGNATURE_HASHES`, mirroring
  `cnert.KEY_ALGORITHMS`.
- `"sha1"` and `"md5"` resolve, then hit the existing refusal with the
  same message an object gets. A name that is no hash at all raises
  `ValueError` listing the usable names.
- Anything that is neither a name, a hash object, nor `None` raises
  `TypeError` naming the type passed. Nothing reaches the message
  construction untyped again.
- Not breaking: every existing call keeps its behaviour.

## Capabilities

### Modified Capabilities

- `certificate-signing`: the signature hash argument gains a second
  accepted form, and wrong-typed values get a defined error instead
  of an `AttributeError`.

## Impact

- `src/cnert/__init__.py`: `_signature_hash_for`, the module-level
  hash tables, and the `signature_hash` annotation on `_CertBuilder`,
  `Cert`, `CSR` and `CA`.
- Public API: additive. The annotation widens to include `str`.
- Ships before 0.11.0, so no released version carries the crash.
