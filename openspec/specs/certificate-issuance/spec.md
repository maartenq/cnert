# certificate-issuance Specification

## Purpose
Defines how authorities, intermediates and leaf certificates are
created and chained, and which inputs a caller may supply for each:
an existing private key, an existing certificate signing request, or
neither. What a key itself is belongs to private-keys.

## Requirements

### Requirement: Keys are generated unless supplied

An authority, an intermediate and a leaf certificate SHALL each
generate a fresh private key when the caller supplies none, and SHALL
use the caller's key when one is supplied.

#### Scenario: Authority on a caller's key

- **WHEN** an authority is created with a caller-supplied private key
- **THEN** the authority's certificate holds that key's public key
- **AND** the authority's private key is the supplied one

#### Scenario: Intermediate on a caller's key

- **WHEN** an authority issues an intermediate with a
  caller-supplied private key
- **THEN** the intermediate's certificate holds that key's public key
- **AND** the intermediate is still signed by its parent authority

#### Scenario: Leaf on a caller's key

- **WHEN** an authority issues a leaf certificate with a
  caller-supplied private key
- **THEN** the leaf holds that key's public key
- **AND** the leaf is signed by the authority's key, not the
  supplied one

#### Scenario: Undersized key

- **WHEN** an authority is created with a 1024-bit RSA key
- **THEN** the authority's certificate holds a 1024-bit public key

#### Scenario: No key supplied

- **WHEN** two leaf certificates are issued from one authority with
  no key supplied
- **THEN** their public keys differ

### Requirement: A signing request supplies its own key

Issuing from a certificate signing request SHALL take the subject
name, the subject alternative names and the private key from that
request. Two certificates issued from one request SHALL therefore
share a key pair and differ in serial number, which is how a renewal
is expressed.

#### Scenario: Renewal from one request

- **WHEN** an authority issues two certificates from the same
  signing request
- **THEN** both certificates hold the same public key
- **AND** their serial numbers differ

### Requirement: A key and a signing request are mutually exclusive

Supplying both a private key and a certificate signing request to a
leaf issuance SHALL raise a `ValueError` rather than silently
preferring one, because the request already carries a key.

#### Scenario: Both supplied

- **WHEN** a leaf certificate is issued with both a private key and a
  signing request
- **THEN** a `ValueError` explaining that the request already carries
  a key is raised

### Requirement: Chaining is unaffected by a supplied key

Path length, issuer attributes and the signing relationship between
an authority and what it issues SHALL behave the same whether keys
were supplied or generated.

#### Scenario: Chain with supplied keys throughout

- **WHEN** an authority, an intermediate and a leaf are each created
  with a caller-supplied key
- **THEN** the leaf's issuer attributes are the intermediate's
  subject attributes
- **AND** the intermediate's issuer attributes are the authority's
  subject attributes
- **AND** the intermediate's path length is one less than the
  authority's
