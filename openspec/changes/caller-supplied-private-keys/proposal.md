## Why

`Cert` and `CSR` both accept a caller-supplied `private_key`, but
`CA()` and `CA.issue_cert()` do not. Since a certificate is normally
reached through an authority, the parameter is effectively
unreachable: a test that needs an authority on a 1024-bit key, or a
leaf whose key uses public exponent 3, cannot express it without
building `Cert` directly and losing the authority wiring that makes
cnert worth using.

`build_private_key()` has had `key_size` and `public_exponent` since
the beginning. This change is mostly about making them reachable.

## What Changes

- `CA()` gains a keyword `private_key`, used for the authority's own
  certificate instead of generating one.
- `CA.issue_intermediate()` gains the same keyword for the
  intermediate's key.
- `CA.issue_cert()` gains the same keyword for the leaf's key.
- Passing both `private_key` and `csr` to `CA.issue_cert()` raises
  `ValueError`, because the request already carries a key and
  silently picking one would hide a caller mistake.
- Not breaking: every keyword defaults to `None`, which keeps
  today's generate-a-fresh-key behaviour.

## Capabilities

### New Capabilities

- `certificate-issuance`: how authorities and leaf certificates are
  created and chained, and which inputs a caller may supply for each,
  including an existing key or an existing signing request.

### Modified Capabilities

None yet. Key generation itself is covered by the `private-keys`
capability introduced in the `widen-key-and-hash-support` change;
this change describes what the issuance API accepts, not what a key
is.

## Impact

- `src/cnert/__init__.py`: `CA.__init__`, `CA.issue_intermediate`,
  `CA.issue_cert`. `Cert` and `CSR` need no change; they already take
  the argument.
- Public API: additive and keyword-only. No new imports for the
  caller beyond `cnert.build_private_key`, which is already
  exported.
- No new dependency and no `cryptography` floor bump.
- Independent of the other two planned changes, though combining it
  with widened key types is what makes an authority on a non-RSA key
  reachable in one call.
