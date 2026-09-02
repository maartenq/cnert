## Context

See proposal.md - Why. What shapes the approach:

- `_signature_hash_for` is the single validator both signing paths go
  through, so one edit covers certificates and requests.
- `_ALLOWED_HASHES` already exists as a tuple of the eight classes
  `cryptography` accepts. A name table should not restate that list.
- SHA-1 and MD5 must keep their current, well-liked refusal message.
  They are not usable, but they are recognisable names, and a caller
  typing `"sha1"` deserves the reason, not "unknown hash".

## Goals / Non-Goals

**Goals:**

- Make the two keywords on one call site read the same way.
- Give every wrong input a defined error, so nothing reaches the
  message construction untyped.

**Non-Goals:**

- Deprecating hash objects. A caller already holding one, or wanting
  a hash cnert does not name, passes it directly.
- Accepting key algorithms as objects for symmetry in the other
  direction. Hiding the `cryptography.hazmat` import is the point of
  the string form; the object form exists only because it was there
  first.

## Decisions

### One name table, with the refused hashes in it

A dict of name to hash class covers the eight signable hashes plus
SHA-1 and MD5. Lookup happens before validation, so a refused name
lands on exactly the path a refused object does and inherits its
message. `SIGNATURE_HASHES`, the public tuple, lists only the signable
names, and `_ALLOWED_HASHES` is derived from the same dict rather than
written out twice.

Alternative considered: resolving names with `getattr(hashes, ...)`.
Rejected because it would accept anything in that module, including
hashes that are not signature algorithms at all.

### `TypeError` for a wrong type, `ValueError` for a wrong value

An unknown name is a bad value. A number is a bad type. The type
check runs after name resolution, so the error names what the caller
actually passed.

### The annotation gains `str`, not a union alias

`hashes.HashAlgorithm | str | _UnsetType | None` appears on five
signatures already carrying the sentinel. A named alias would read
better but would be a sixth public name to explain in a library whose
whole API fits on one page.

## Risks / Trade-offs

- **Two accepted forms for one argument.** Slightly more to document
  and test. → The docstring shows the string form first, since it is
  the one that needs no import.
- **The name table can drift from `cryptography`.** A hash added
  upstream is not reachable by name until cnert lists it. → The object
  form is the escape hatch, and the error message names it.

## Migration Plan

None. Ships before 0.11.0, so no released version ever had the crash.
