## 1. Key generation

- [x] 1.1 Add the algorithm-name to constructor table and give
  `build_private_key()` its `algorithm` keyword, defaulting to RSA.
  Verify with tests asserting the key type for each of `rsa`,
  `ed25519`, `ed448`, `secp256r1`, `secp384r1` and `secp521r1`.
- [x] 1.2 Reject an unknown algorithm name with a `ValueError` that
  lists the supported names. Verify with a `pytest.raises` test on
  the message.
- [x] 1.3 Reject `key_size` or `public_exponent` combined with a
  non-RSA algorithm. Verify with a `pytest.raises` test per argument.

## 2. Signature hash

- [x] 2.1 Add the `_UNSET` sentinel and
  `_signature_hash_for(private_key, signature_hash)` returning the
  effective hash. Verify with direct unit tests covering RSA, EC and
  both Edwards types against unset, a hash, and `None`.
- [x] 2.1a Refuse SHA-1 and MD5 with a `ValueError` naming the hash,
  checked against a module-level tuple of the SHA-2 and SHA-3
  classes. Verify with a `pytest.raises` test for each.
- [x] 2.2 Route `_CertBuilder.sign()` through the helper and thread
  `signature_hash` from `Cert.__init__` and
  `Cert._build_certificate`. Verify a default issue still reports
  SHA-256 and that SHA-384 comes back when asked.
- [x] 2.3 Route `CSR._gen_csr()` through the same helper and add
  `signature_hash` to `CSR.__init__`. Verify a request signed with
  SHA-512 reports SHA-512.
- [x] 2.4 Thread `signature_hash` through `CA.__init__` and
  `CA.issue_cert()`. Verify an Ed25519 authority issuing an RSA leaf
  produces a leaf with no separate hash algorithm.

## 3. Typing and accessors

- [x] 3.1 Widen the private and public key annotations on
  `build_private_key`, `_CertBuilder`, `Cert`, `CSR` and `CA` to the
  cryptography issuer and public key unions. Verify `task typing` is
  clean.
- [x] 3.2 Make `private_key_pem_PKCS1` raise a `ValueError` naming
  PKCS#8 for non-RSA keys, on both `Cert` and `CSR`. Verify with a
  `pytest.raises` test and a passing PKCS#8 test for an Edwards key.

## 4. Documentation and release notes

- [x] 4.1 Update the docstrings for every touched public callable so
  the new keywords render in the API reference. Verify with
  `task docs:test`.
- [x] 4.2 Add a `CHANGELOG.md` entry under `[Unreleased]` covering
  the new keywords and the widened annotations, flagging the
  annotation widening as the one thing a downstream type checker may
  notice.
- [x] 4.3 Run `task check` and `task test` and confirm both are
  green.
