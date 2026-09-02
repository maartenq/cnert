## MODIFIED Requirements

### Requirement: Signature hash is selectable

Certificates and certificate signing requests SHALL accept an
optional `signature_hash` argument naming the hash, given either as a
hash object or as one of the names in `SIGNATURE_HASHES`. It SHALL
default to SHA-256, so existing callers keep their current output.

#### Scenario: Default stays SHA-256

- **WHEN** a certificate is issued with no `signature_hash` argument
- **THEN** its signature hash algorithm is SHA-256

#### Scenario: Explicit strong hash

- **WHEN** a certificate is issued with `signature_hash` set to
  SHA-384
- **THEN** the certificate is produced and its signature hash
  algorithm is SHA-384

#### Scenario: Certificate signing request hash

- **WHEN** a certificate signing request is built with
  `signature_hash` set to SHA-512
- **THEN** its signature hash algorithm is SHA-512

#### Scenario: Hash given by name

- **WHEN** a certificate is issued with `signature_hash` set to the
  string `"sha512"`
- **THEN** the certificate is produced and its signature hash
  algorithm is SHA-512

#### Scenario: A refused hash given by name

- **WHEN** a certificate is issued with `signature_hash` set to the
  string `"sha1"`
- **THEN** the same `ValueError` is raised as for the SHA-1 object

#### Scenario: A name that is no hash

- **WHEN** a certificate is issued with `signature_hash` set to a
  string naming no known hash
- **THEN** a `ValueError` listing the usable names is raised

## ADDED Requirements

### Requirement: Wrong-typed signature hashes are reported

A `signature_hash` that is neither a name, a hash object, nor `None`
SHALL raise a `TypeError` naming the type that was passed. The
validator SHALL NOT fail while building its own error message.

#### Scenario: A number

- **WHEN** a certificate is issued with `signature_hash` set to an
  integer
- **THEN** a `TypeError` naming `int` is raised

#### Scenario: An arbitrary object

- **WHEN** a certificate is issued with `signature_hash` set to an
  object of some unrelated class
- **THEN** a `TypeError` naming that class is raised
