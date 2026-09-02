## Context

See proposal.md - Why. The relevant current shape:

- `_CertBuilder.build()` already collects its built-in extensions
  into one list before adding them, from the extensions-hatch change.
  Suppression is a guard on building that list, not a new mechanism.
- The subject alternative name is built from `sans`, which is a
  separate argument from `extensions`. Whether it counts as
  "built-in" is the only real question here.
- `CSR._gen_csr()` has the same collect-then-add shape.

## Goals / Non-Goals

**Goals:**

- Make the bare certificate a parser test needs reachable in one
  call.
- Keep the switch honest: suppress everything cnert adds, with no
  exceptions a caller has to memorise.

**Non-Goals:**

- Suppressing individual built-ins. A caller wanting a leaf without
  extended key usage but with everything else is describing a
  different feature, and can already override an extension rather
  than remove it.
- Validating the result. A certificate with no basic constraints is
  malformed for real use and perfectly good as a fixture.

## Decisions

### The subject alternative name is a built-in, so it goes too

`builtin_extensions=False` on a call that also passes `sans` produces
a certificate with the common name in its subject and no subject
alternative name. That is the shape a parser test wants: a name
present in one place and absent in the other.

Alternative considered: keeping the subject alternative name because
`sans` was passed explicitly. Rejected because it makes the switch
mean "most built-ins", which is the kind of exception that has to be
looked up every time.

### A boolean, not a set of names

`builtin_extensions=False` rather than
`suppress={"key_usage", "basic_constraints"}`. The named-set version
is a bigger feature answering a question nobody has asked, and it
would need a vocabulary of names to maintain. The boolean covers the
test case that prompted this.

### The default stays true and is spelled out in the spec

A requirement pins that omitting the argument reproduces the previous
output, so the suppression path cannot quietly become the default
through a refactor.

## Risks / Trade-offs

- **A caller builds a chain that does not verify.** An authority
  without basic constraints cannot validate a path. → Intended, and
  the docstring says so. cnert is a fixture library; producing an
  invalid certificate on request is a feature.
- **The switch and the hatch could be confused.** One subtracts, one
  adds and overrides. → They compose, and the docs show them
  together in the one call that produces a bare certificate carrying
  exactly one extension.

## Migration Plan

None. The default reproduces current behaviour.
