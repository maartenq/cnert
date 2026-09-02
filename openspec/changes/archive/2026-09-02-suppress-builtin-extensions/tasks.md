## 1. Certificates

- [x] 1.1 Give `_CertBuilder.build()` a `builtin_extensions`
  argument that guards assembly of the built-in list, leaving the
  caller-supplied pairs untouched. Verify a build with it false and
  no supplied extensions yields a certificate carrying none.
- [x] 1.2 Thread it from `Cert.__init__` and
  `Cert._build_certificate`. Verify that looking for a suppressed
  extension reports it absent rather than raising, which is the
  parser case this exists for.
- [x] 1.3 Confirm the subject alternative name is suppressed with
  the rest. Verify a leaf issued with names and the switch false has
  no subject alternative name but keeps its common name.

## 2. Authorities and requests

- [x] 2.1 Thread `builtin_extensions` through `CA.__init__`,
  `CA.issue_intermediate()` and `CA.issue_cert()`. Verify an
  authority built with it false carries no basic constraints and is
  produced without complaint.
- [x] 2.2 Apply the same guard in `CSR._gen_csr()` and add the
  keyword to `CSR.__init__`. Verify a request built with names and
  the switch false carries no extensions.

## 3. Composition and defaults

- [x] 3.1 Verify suppression composes with the hatch: a leaf issued
  with the switch false and one supplied extension carries exactly
  that one.
- [x] 3.2 Verify the default is unchanged, comparing a certificate
  issued with no argument against one issued with it set true.

## 4. Documentation and release notes

- [x] 4.1 Document the keyword on every touched public callable and
  in the docs page, saying plainly that the result is not a valid
  certificate for real use and that this is deliberate. Verify with
  `task docs:test`.
- [x] 4.2 Add a `CHANGELOG.md` entry under `[Unreleased]`.
- [x] 4.3 Run `task check` and `task test` and confirm both are
  green.
