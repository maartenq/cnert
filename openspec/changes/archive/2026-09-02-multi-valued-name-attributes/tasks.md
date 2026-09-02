## 1. Multi-valued values

- [x] 1.1 Accept `str | Sequence[str]` in `NameAttrs.__init__`,
  normalising a sequence to a tuple and emitting one
  `x509.NameAttribute` per value in the order given. Verify a name
  with two organizational units yields those two attributes in that
  order, and that reversing the values reverses them. Assert on
  attribute order, not on `rfc4514_string()`, which prints
  most-specific first and so reads reversed.
- [x] 1.2 Keep alphabetical ordering across attribute types while
  values within one key follow the caller. Verify with a mixed
  single-value and multi-value name.
- [x] 1.3 Widen the class-level attribute annotations to
  `str | tuple[str, ...]`. Verify `task typing` is clean and that
  `allowed_keys()` still lists every attribute type.

## 2. Frozen, hashable, renderable

- [x] 2.1 Verify a multi-valued name is still hashable and compares
  by content: two equal names hash equal and collapse in a set.
- [x] 2.2 Render a multi-valued attribute in `repr()` as a bracketed
  list of quoted strings, leaving single values exactly as they are.
  Verify the existing repr tests still pass unchanged and add one for
  the multi-valued form.

## 3. Wrong-typed names

- [x] 3.1 Raise `TypeError` naming the type passed when
  `subject_attrs` or `issuer_attrs` is not a `NameAttrs`, checked in
  `Cert.__init__` and `CSR.__init__`. Verify with a raw `x509.Name`
  and with a string, and confirm neither reaches
  `_build_certificate`.

## 4. Documentation and release notes

- [x] 4.1 Document the sequence form on `NameAttrs` and in the docs
  page, stating that it produces `OU=A,OU=B` and not the plus-joined
  form. Verify with `task docs:test`.
- [x] 4.2 Add a `CHANGELOG.md` entry under `[Unreleased]`, including
  the widened attribute annotations.
- [x] 4.3 Run `task check` and `task test` and confirm both are
  green.
