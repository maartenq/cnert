## MODIFIED Requirements

### Requirement: Built-in extension set

Unless suppressed, every issued certificate SHALL carry basic
constraints and a subject key identifier. A certificate issued by an
authority SHALL also carry an authority key identifier. An authority
certificate SHALL carry key usage marking it as a certificate and CRL
signer; a leaf certificate SHALL carry key usage for digital
signature and key encipherment plus extended key usage for client
authentication, server authentication and code signing. A certificate
given subject alternative names SHALL carry them.

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

## ADDED Requirements

### Requirement: The built-in set can be suppressed

Certificates, authorities and certificate signing requests SHALL
accept a `builtin_extensions` argument, defaulting to true. When
false, the result SHALL carry only the extensions the caller supplied
and nothing cnert would add by itself.

#### Scenario: A certificate with no extensions at all

- **WHEN** a leaf certificate is issued with `builtin_extensions`
  false and no supplied extensions
- **THEN** the certificate carries no extensions
- **AND** looking for any one of them reports it as absent rather
  than raising

#### Scenario: Subject alternative names are suppressed too

- **WHEN** a leaf certificate is issued with subject alternative
  names and `builtin_extensions` false
- **THEN** the certificate carries no subject alternative name
  extension
- **AND** its subject attributes still carry the common name

#### Scenario: Suppression composes with the hatch

- **WHEN** a leaf certificate is issued with `builtin_extensions`
  false and one supplied extension
- **THEN** the certificate carries exactly that one extension

#### Scenario: An authority with no extensions

- **WHEN** an authority is created with `builtin_extensions` false
- **THEN** its certificate carries no basic constraints extension
- **AND** cnert issues it without complaint, leaving the
  consequences to the caller

#### Scenario: A bare certificate signing request

- **WHEN** a certificate signing request is built with subject
  alternative names and `builtin_extensions` false
- **THEN** the request carries no extensions

### Requirement: The default is unchanged

Omitting `builtin_extensions` SHALL produce a certificate identical
in extension content to one built before this capability existed.

#### Scenario: Default matches an explicit true

- **WHEN** two leaf certificates are issued from one authority, one
  with no `builtin_extensions` argument and one with it set true
- **THEN** both carry the same set of extension object identifiers
