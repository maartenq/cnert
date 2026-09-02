## 1. Certificate extensions

- [ ] 1.1 Rework `_CertBuilder.build()` to collect the built-in
  extensions into a list of extension and criticality pairs and add
  them in one pass. Verify the existing test suite still passes
  unchanged.
- [ ] 1.2 Add the deduplication step that keeps the last pair per
  object identifier. Verify with a unit test feeding two pairs of the
  same type and asserting one survives.
- [ ] 1.3 Give `_CertBuilder.build()` its `extensions` argument and
  thread it from `Cert.__init__` and `Cert._build_certificate`.
  Verify an issued certificate carries a supplied TLS Feature
  extension alongside the built-in set.
- [ ] 1.4 Thread `extensions` through `CA.__init__` and
  `CA.issue_cert()`. Verify an authority created with overriding
  basic constraints has exactly one such extension carrying the
  supplied path length.

## 2. Certificate signing request extensions

- [ ] 2.1 Apply the same collect, append and deduplicate shape to
  `CSR._gen_csr()` and add the `extensions` keyword to
  `CSR.__init__`. Verify a request built with an extension carries
  it, and that a request built without one is unchanged.

## 3. Documentation and release notes

- [ ] 3.1 Document the keyword on every touched public callable,
  stating that a supplied extension replaces a built-in one of the
  same type. Verify with `task docs:test`.
- [ ] 3.2 Add a `CHANGELOG.md` entry under `[Unreleased]`.
- [ ] 3.3 Run `task check` and `task test` and confirm both are
  green.
