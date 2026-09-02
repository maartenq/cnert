# certificate-extensions Specification

## Purpose
Defines which X.509 extensions cnert places on a certificate or
certificate signing request without being asked, and how a caller
adds an extension cnert does not model or overrides one it does.
Signing itself lives in certificate-signing.

## Requirements

### Requirement: Built-in extension set

Every issued certificate SHALL carry basic constraints and a subject
key identifier. A certificate issued by an authority SHALL also carry
an authority key identifier. An authority certificate SHALL carry key
usage marking it as a certificate and CRL signer; a leaf certificate
SHALL carry key usage for digital signature and key encipherment plus
extended key usage for client authentication, server authentication
and code signing. A certificate given subject alternative names SHALL
carry them.

#### Scenario: Leaf certificate defaults

- **WHEN** an authority issues a leaf certificate with one subject
  alternative name
- **THEN** the certificate has basic constraints with the certificate
  authority flag false
- **AND** it has a subject key identifier, an authority key
  identifier, key usage, extended key usage and that subject
  alternative name

#### Scenario: Authority certificate defaults

- **WHEN** a root authority is created
- **THEN** its certificate has basic constraints with the certificate
  authority flag true
- **AND** its key usage permits certificate signing and CRL signing
- **AND** it has no authority key identifier, having no issuer above
  it

### Requirement: Caller-supplied extensions

Certificates, authorities and certificate signing requests SHALL
accept an optional `extensions` sequence of extension and criticality
pairs. Each supplied extension SHALL appear on the result with the
criticality given.

#### Scenario: Adding an unmodelled extension

- **WHEN** a leaf certificate is issued with an extensions sequence
  holding a TLS Feature extension for OCSP must-staple, marked
  non-critical
- **THEN** the certificate carries that TLS Feature extension as
  non-critical
- **AND** it still carries the full built-in extension set

#### Scenario: Adding several extensions

- **WHEN** a certificate is issued with an extensions sequence
  holding more than one extension
- **THEN** every supplied extension appears on the certificate

#### Scenario: Extensions on a certificate signing request

- **WHEN** a certificate signing request is built with an extensions
  sequence
- **THEN** the request carries those extensions

### Requirement: A supplied extension overrides a built-in one

Where a supplied extension has the same object identifier as one
cnert adds by itself, the supplied one SHALL replace it. The result
SHALL never contain two extensions with the same object identifier,
which X.509 forbids.

#### Scenario: Overriding key usage

- **WHEN** a leaf certificate is issued with an extensions sequence
  holding a key usage extension
- **THEN** the certificate has exactly one key usage extension
- **AND** its value is the supplied one

#### Scenario: Overriding basic constraints on an authority

- **WHEN** an authority is created with an extensions sequence
  holding basic constraints with a different path length
- **THEN** the certificate has exactly one basic constraints
  extension carrying the supplied path length

### Requirement: Empty and absent extensions change nothing

Omitting the extensions argument, or passing an empty sequence, SHALL
produce a certificate identical in extension content to one built
before this capability existed.

#### Scenario: No extensions argument

- **WHEN** two leaf certificates are issued from the same authority,
  one with no extensions argument and one with an empty sequence
- **THEN** both carry the same set of extension object identifiers
