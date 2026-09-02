# certificate-signing Specification

## Purpose
Defines how a certificate or certificate signing request is signed:
which key does the signing, how the signature hash is chosen, and
which key and hash combinations are rejected. Key generation itself
lives in private-keys.

## Requirements

### Requirement: Signature hash is selectable

Certificates and certificate signing requests SHALL accept an
optional `signature_hash` argument naming the hash. It SHALL
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

### Requirement: Edwards keys sign without a hash

Ed25519 and Ed448 keys SHALL be signed with no separate hash
algorithm. Callers SHALL NOT have to pass anything for this to work,
and passing `None` explicitly SHALL be accepted.

#### Scenario: Edwards key with no argument

- **WHEN** a certificate is issued from an Ed25519 key with no
  `signature_hash` argument
- **THEN** the certificate is produced with no separate signature
  hash algorithm

#### Scenario: Edwards key with an explicit hash

- **WHEN** a certificate is issued from an Ed448 key with
  `signature_hash` set to a hash
- **THEN** a `ValueError` stating that Edwards keys take no hash is
  raised

### Requirement: Non-Edwards keys require a hash

RSA and elliptic curve keys SHALL be rejected when the signature hash
is `None`, with an error naming the key type, rather than failing
inside the cryptography library.

#### Scenario: RSA key with no hash

- **WHEN** a certificate is issued from an RSA key with
  `signature_hash` set to `None`
- **THEN** a `ValueError` stating that this key type requires a hash
  is raised

### Requirement: Hashes unusable for signatures are refused

The SHA-2 and SHA-3 families are the only hashes usable for X.509
signatures. SHA-1 and MD5 SHALL be refused with a `ValueError` naming
the hash, rather than surfacing the underlying library's
`UnsupportedAlgorithm`.

#### Scenario: SHA-1 requested

- **WHEN** a certificate is issued with `signature_hash` set to SHA-1
- **THEN** a `ValueError` naming SHA-1 as unusable for signatures is
  raised

#### Scenario: MD5 requested

- **WHEN** a certificate signing request is built with
  `signature_hash` set to MD5
- **THEN** a `ValueError` naming MD5 as unusable for signatures is
  raised

### Requirement: The issuing key signs the certificate

A certificate issued by an authority SHALL be signed by that
authority's private key, and a self-signed certificate SHALL be
signed by its own. The signature hash SHALL be validated against the
key that actually signs, not against the certificate's subject key.

#### Scenario: Edwards authority signing an RSA leaf

- **WHEN** an Ed25519 authority issues a leaf certificate holding an
  RSA subject key, with no `signature_hash` argument
- **THEN** the leaf is signed with no separate hash algorithm
- **AND** the leaf's own public key is the RSA key

#### Scenario: RSA authority signing an Edwards leaf

- **WHEN** an RSA authority issues a leaf certificate holding an
  Ed25519 subject key
- **THEN** the leaf is signed with SHA-256
