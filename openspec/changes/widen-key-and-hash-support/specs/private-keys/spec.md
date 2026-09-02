## Purpose

Defines what private key material cnert generates and accepts: which
algorithms are available, how RSA sizing is controlled, and what a
caller may hand in when it wants a key of its own. Signing behaviour
lives in certificate-signing.

## ADDED Requirements

### Requirement: Key algorithm selection

Key generation SHALL support RSA, elliptic curve, Ed25519 and Ed448,
selected by an optional `algorithm` argument. RSA SHALL remain the
default so existing callers are unaffected.

#### Scenario: Default stays RSA

- **WHEN** a key is generated with no `algorithm` argument
- **THEN** the result is a 2048-bit RSA key with public exponent
  65537

#### Scenario: Elliptic curve key

- **WHEN** a key is generated with `algorithm` naming an EC curve
- **THEN** the result is an EC private key on that curve
- **AND** it can be used as a certificate subject key and as a
  signing key

#### Scenario: Edwards key

- **WHEN** a key is generated with `algorithm` selecting Ed25519 or
  Ed448
- **THEN** the result is a private key of that type
- **AND** it can be used as a certificate subject key and as a
  signing key

#### Scenario: Unknown algorithm

- **WHEN** a key is generated with an `algorithm` value that names no
  supported algorithm
- **THEN** a `ValueError` naming the supported algorithms is raised

### Requirement: RSA sizing parameters apply to RSA only

The `key_size` and `public_exponent` arguments SHALL control RSA key
generation and SHALL be rejected for algorithms that do not use them,
rather than being silently ignored.

#### Scenario: Sizing an RSA key

- **WHEN** a key is generated with `key_size=1024` and no `algorithm`
- **THEN** the result is a 1024-bit RSA key

#### Scenario: Sizing a non-RSA key

- **WHEN** a key is generated with `key_size` or `public_exponent`
  together with a non-RSA `algorithm`
- **THEN** a `ValueError` explaining that the argument is RSA-only is
  raised

### Requirement: Non-RSA keys are accepted throughout the API

Every place that accepts a caller-supplied private key SHALL accept
any algorithm that cnert can generate, and SHALL type-check against
the key type unions published by the cryptography library rather than
against RSA alone.

#### Scenario: Certificate signing request with an Edwards key

- **WHEN** a certificate signing request is built with a
  caller-supplied Ed25519 key
- **THEN** the request is signed by that key and its public key is
  the Ed25519 public key

#### Scenario: Authority with an elliptic curve key

- **WHEN** a certificate authority is built on an EC key and issues a
  leaf certificate
- **THEN** the leaf verifies against the authority's EC public key

### Requirement: Key material accessors work for every algorithm

The PKCS#1, PKCS#8 and public-key PEM accessors SHALL work for each
supported algorithm, except that PKCS#1 is RSA-only and SHALL raise a
clear error for other algorithms rather than emitting a malformed
document.

#### Scenario: PKCS#8 for an Edwards key

- **WHEN** the PKCS#8 PEM of an Ed25519 key is read
- **THEN** a PEM private key document is returned

#### Scenario: PKCS#1 for a non-RSA key

- **WHEN** the PKCS#1 PEM of a non-RSA key is read
- **THEN** a `ValueError` stating that PKCS#1 is RSA-only is raised
