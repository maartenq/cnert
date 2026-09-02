## Context

See proposal.md - Why. What shapes the approach:

- `_CertBuilder` adds its extensions eagerly, each call returning a
  new `x509.CertificateBuilder`. There is no point today at which the
  full extension set exists as data that could be merged.
- `cryptography`'s builder raises when the same object identifier is
  added twice, so an override cannot be done by appending.
- `CSR` builds its own request separately and shares none of
  `_CertBuilder`'s code.

## Goals / Non-Goals

**Goals:**

- One keyword that both adds and overrides, with no second argument
  to say which.
- A predictable rule for the collision case, written into the spec so
  it is not an accident of ordering.

**Non-Goals:**

- Removing a built-in extension. A caller that wants no key usage at
  all is asking for a malformed certificate; overriding it with an
  empty key usage is the supported way to get close.
- Wrapping every extension cnert does not model in a friendly
  keyword. The hatch is the answer to that.
- A shared builder for certificates and requests. Worth doing, but it
  is a refactor of its own and would make this change hard to review.

## Decisions

### Collect extensions, then add them once

`_CertBuilder.build()` gathers the built-in extensions into a list of
pairs instead of calling `add_extension` as it goes. Caller-supplied
pairs are appended to that list, the list is reduced to one entry per
object identifier keeping the last, and only then are they added to
the cryptography builder.

Alternative considered: keep adding eagerly and skip a built-in when
the caller supplied the same object identifier. Rejected because the
skip check would have to be repeated in each `_add_*` helper, and a
new helper added later would silently miss it.

### Last one wins, and callers come last

Deduplication keeps the last occurrence. Since caller pairs are
appended after the built-ins, a caller always wins. Among caller
pairs, a later entry wins over an earlier one, which is the ordinary
reading of a sequence.

### The pair is a plain tuple

`(extension, critical)` rather than `x509.Extension`, which also
needs an object identifier the caller would have to repeat, or a
dict, which cannot express two extensions of the same type during
construction. The tuple reads well inline in a test.

### `CSR` gets the same treatment separately

The request builder gains the same collect-then-add shape. The
duplication is two short blocks, and pulling them into a shared
helper would drag the certificate and request paths together, which
this change deliberately avoids.

## Risks / Trade-offs

- **A caller overrides basic constraints and breaks the chain.**
  Overriding is the point, so cnert cannot validate its way out. →
  The docstring says an override replaces cnert's version wholesale,
  and the spec makes it explicit.
- **Extension ordering in the certificate changes.** Built-ins keep
  their relative order, but an overridden extension moves to the
  position of the caller's entry. Nothing in X.509 depends on
  extension order, and no cnert accessor exposes it. → Accepted.
- **The hatch invites cnert never to model anything again.** →
  Extensions that show up repeatedly in tests still deserve a proper
  keyword later; the hatch is for the long tail.

## Migration Plan

None. The keyword defaults to empty and the built-in set is
unchanged.
