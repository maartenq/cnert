## 1. Name resolution

- [x] 1.1 Add the name-to-class table covering the eight signable
  hashes plus SHA-1 and MD5, export the signable names as
  `cnert.SIGNATURE_HASHES`, and derive `_ALLOWED_HASHES` from it so
  the list is written once. Verify `SIGNATURE_HASHES` holds the eight
  names and excludes SHA-1 and MD5.
- [x] 1.2 Resolve a string `signature_hash` through the table at the
  top of `_signature_hash_for`. Verify `"sha512"` produces a
  SHA-512-signed certificate and `"sha1"` raises the existing refusal
  message.
- [x] 1.3 Raise `ValueError` listing the usable names for a string
  that names no known hash. Verify with a `pytest.raises` test.

## 2. Type safety

- [x] 2.1 Raise `TypeError` naming the type passed when
  `signature_hash` is neither a name, a hash object, nor `None`.
  Verify with `pytest.raises` for an integer and for an unrelated
  class, and confirm neither reaches the message construction.

## 3. Annotations, documentation and release notes

- [x] 3.1 Widen the `signature_hash` annotation to include `str` on
  `_signature_hash_for`, `_CertBuilder.sign`, `Cert`, `CSR`, `CA`,
  `CA.issue_intermediate` and `CA.issue_cert`. Verify `task typing`
  is clean.
- [x] 3.2 Document the string form on every touched public callable
  and in the docs page, showing it before the object form. Verify
  with `task docs:test`.
- [x] 3.3 Add a `CHANGELOG.md` entry under `[Unreleased]`.
- [x] 3.4 Run `task check` and `task test` and confirm both are
  green.
