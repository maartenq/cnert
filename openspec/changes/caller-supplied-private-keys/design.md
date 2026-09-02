## Context

See proposal.md - Why. The relevant current shape:

- `Cert.__init__` already takes `private_key` and generates one when
  it is `None`, so the plumbing below the authority exists.
- `CA.__init__` builds its `Cert` with a fixed set of arguments and
  never mentions a key.
- `CA.issue_cert()` already computes a `private_key` local: it is the
  request's key when a signing request is given, and `None`
  otherwise. The new keyword lands in an `if/else` that is already
  there.
- `CA.issue_intermediate()` constructs a child `CA`, so it inherits
  whatever `CA.__init__` accepts.

## Goals / Non-Goals

**Goals:**

- Reach `build_private_key()`'s existing `key_size` and
  `public_exponent` from the normal authority-first entry point.
- Fail loudly on the one genuinely ambiguous call rather than picking
  a key for the caller.

**Non-Goals:**

- Forwarding `key_size` and `public_exponent` as keywords on `CA()`
  and `issue_cert()`. Passing a built key is one extra line and does
  not multiply the parameter list at every level, which matters more
  once the key algorithm keyword also exists.
- Reusing one key across a whole chain by default. A caller wanting
  that passes the same key at each level explicitly.

## Decisions

### Pass the key, not the key parameters

`CA(private_key=build_private_key(key_size=1024))` rather than
`CA(key_size=1024)`. The alternative pushes every key-shaping
argument onto three call sites, and would collide with the
`algorithm` keyword the key-widening change adds. One object beats a
growing parameter list.

### A key and a signing request are an error, not a precedence rule

`issue_cert(private_key=..., csr=...)` raises. A precedence rule
would be defensible either way, which is the sign that a caller
writing both has made a mistake. Raising surfaces it at the call
instead of producing a certificate whose key came from somewhere the
caller did not expect.

### `issue_intermediate` takes a key, not a built authority

It already constructs the child `CA` itself, so the keyword is a
pass-through. Letting a caller hand in a fully built `CA` would be a
different feature and would bypass the path-length arithmetic.

## Risks / Trade-offs

- **A caller reuses one key across a chain by accident.** Nothing
  prevents passing the same key to the authority and the leaf, which
  produces a chain no real deployment would have. → That is a
  legitimate fixture for testing key-reuse detection, so it stays
  allowed and the docstring notes it.
- **Weak keys become easy to make.** Intended: an undersized key is
  exactly the fixture a hygiene test needs. → The docstring says so.

## Migration Plan

None. All three keywords default to `None`, reproducing today's
behaviour.
