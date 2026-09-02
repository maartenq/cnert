## 1. Authority keys

- [ ] 1.1 Add the `private_key` keyword to `CA.__init__` and pass it
  through to the authority's `Cert`. Verify an authority built on a
  1024-bit key reports a 1024-bit public key.
- [ ] 1.2 Add the same keyword to `CA.issue_intermediate()` and pass
  it to the child authority. Verify the intermediate holds the
  supplied public key and is still signed by its parent.

## 2. Leaf keys

- [ ] 2.1 Add the `private_key` keyword to `CA.issue_cert()`,
  folding it into the existing signing-request branch. Verify the
  leaf holds the supplied public key while the signature still comes
  from the authority.
- [ ] 2.2 Raise `ValueError` when both `private_key` and `csr` are
  given. Verify with a `pytest.raises` test on the message.

## 3. Regression cover for existing behaviour

- [ ] 3.1 Add a test issuing two certificates from one signing
  request, asserting equal public keys and differing serial numbers.
  This behaviour already works and is being pinned, not built.
- [ ] 3.2 Add a test building an authority, intermediate and leaf
  with supplied keys throughout, asserting the issuer attribute chain
  and the decreasing path length.

## 4. Documentation and release notes

- [ ] 4.1 Document the keyword on all three callables, including that
  a supplied key is used for the subject and never for the signature,
  and that reusing one key across a chain is allowed. Verify with
  `task docs:test`.
- [ ] 4.2 Add a `CHANGELOG.md` entry under `[Unreleased]`.
- [ ] 4.3 Run `task check` and `task test` and confirm both are
  green.
