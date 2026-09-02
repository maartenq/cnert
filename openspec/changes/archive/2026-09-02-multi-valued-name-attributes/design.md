## Context

See proposal.md - Why. The shape that constrains this:

- `NameAttrs.__init__` takes `**kwargs: str`, sorts the keys, and
  builds one `x509.NameAttribute` per key. Values also land in
  `dict_`, which drives equality, hashing and both string forms.
- `Freezer` makes instances immutable after construction, and
  `__hash__` hashes `tuple(dict_.items())`, so every stored value has
  to be hashable.
- Class-level annotations declare each attribute as `str`, and
  `allowed_keys()` reads their names, not their types.

## Goals / Non-Goals

**Goals:**

- One subject type. A caller never has to reach for
  `cryptography.x509` to express a name.
- Order that is explicit where it matters and stable where it does
  not.

**Non-Goals:**

- The plus-joined single-RDN form. See the decision below.
- Attribute types cnert does not list. `allowed_keys()` is the
  vocabulary, and adding one is a one-line change when it is needed.
- Preserving caller order across different attribute types.
  Alphabetical ordering is existing behaviour that equality and the
  rendered forms already depend on.

## Decisions

### One relative distinguished name per value

`ORGANIZATIONAL_UNIT_NAME=["A", "B"]` yields two attributes, `A`
then `B`, each its own relative distinguished name. That is what
`x509.Name` does with a flat list of attributes, and it is the form
real certificates overwhelmingly use. Note that `rfc4514_string()`
prints most-specific first, so it renders that name as
`OU=B,OU=A,...`; the attribute order is the caller's, the rendering
convention is RFC 4514's.

The other reading of "multi-valued" is `OU=A+OU=B`, one relative
distinguished name holding both, which needs
`x509.RelativeDistinguishedName` and a different argument shape. It
is genuinely rare, and a parser that collects repeated attribute
types is exercised by either form. Left out deliberately; if a test
ever needs the plus-joined form, it deserves its own argument rather
than an overload of this one.

### Values are stored as tuples, rendered as lists

A list value would make instances unhashable, and `Freezer` plus
content-based equality are load-bearing. The value is normalised to a
tuple on the way in. `repr()` renders it back as a bracketed list of
quoted strings, so the output is what a caller would type, not the
internal shape.

Single-string values are stored unchanged rather than as one-element
tuples, so nothing about the existing repr, str, equality or hashing
moves. The cost is a value type of `str | tuple[str, ...]` instead of
one uniform shape; the benefit is that no existing test or consumer
sees a difference.

### The name check lives where the name arrives

`Cert.__init__` and `CSR.__init__` check their name arguments,
because `CA` builds a `Cert` and inherits the check. Raising at
construction names the argument while the caller's frame is still the
obvious suspect, rather than deep inside `_build_certificate`.

## Risks / Trade-offs

- **Two value shapes to remember.** Reading an attribute back gives a
  `str` or a `tuple`, depending on how it was set. → A caller that
  wants uniformity passes sequences throughout; the annotation states
  both.
- **A downstream type checker notices the widened annotations.** Code
  reading `subject_attrs.COMMON_NAME` and passing it where `str` is
  required now sees a union. → Called out in the changelog with the
  other annotation widening in this release.
- **The plus-joined form still needs a hand-built name.** → Accepted
  and documented; the reporter's test does not need it.

## Migration Plan

None. Single-string values are untouched, and the new value shape is
opt-in per attribute.
