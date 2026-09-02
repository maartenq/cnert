## Why

`NameAttrs` is keyword-based, so it cannot carry one attribute type
twice: Python forbids a repeated keyword outright. A distinguished
name with two organizational units is therefore unreachable, and a
parser proving it reads a DN losslessly has no cnert fixture to test
against. tlscertmon reported that this is the single remaining reason
a raw `CertificateBuilder` survives in its conftest, after cnert took
over five other fixtures.

The obvious workaround fails the same way the signature hash used to.
Passing a raw `x509.Name` as `subject_attrs` raises
`AttributeError: 'Name' object has no attribute 'x509_name'` from
inside certificate construction: a wrong type reaching internals
untyped.

## What Changes

- A `NameAttrs` value may be a sequence of strings as well as a
  single string: `NameAttrs(ORGANIZATIONAL_UNIT_NAME=["A", "B"])`
  emits two attributes of that type, in the order given.
- Keys keep their existing alphabetical ordering; only values within
  one key follow the caller's order.
- A multi-valued attribute reads back from the instance as a tuple,
  so instances stay hashable and frozen. `repr()` renders it as the
  list a caller would type.
- `subject_attrs` and `issuer_attrs` raise `TypeError` naming the
  type passed when given anything that is not a `NameAttrs`.
- Not breaking: single-string values behave exactly as before,
  including `repr()`, `str()`, equality and hashing.

## Capabilities

### New Capabilities

- `name-attributes`: what a subject or issuer distinguished name
  accepts, how values map onto X.509 name attributes, and how a
  wrong type is reported.

## Impact

- `src/cnert/__init__.py`: `NameAttrs.__init__`, its class-level
  attribute annotations, `__repr__`, and a name-argument check used
  by `Cert` and `CSR`.
- Public API: additive. The accepted value type widens; the attribute
  annotations widen to `str | tuple[str, ...]`, which a downstream
  type checker may notice if it reads an attribute and passes it
  somewhere expecting `str`.
- Emits one attribute per value, each its own relative distinguished
  name. The plus-joined `OU=A+OU=B` single-RDN form stays out of
  reach; see design.md.
- No new dependency and no `cryptography` floor bump.
