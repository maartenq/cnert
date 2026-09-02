## Purpose

Defines what a subject or issuer distinguished name accepts, how its
values become X.509 name attributes and in what order, and how a
wrong type is reported. Certificates and requests consume these
names; issuing them lives in certificate-issuance.

## ADDED Requirements

### Requirement: Name attributes are given by keyword

A distinguished name SHALL be built from keyword arguments whose
names are X.509 attribute types. An unknown attribute type SHALL be
rejected. The resulting attributes SHALL be ordered alphabetically by
attribute type, so an equal name always renders equally.

#### Scenario: A single attribute

- **WHEN** a name is built with one common name
- **THEN** the resulting X.509 name carries that one attribute

#### Scenario: Alphabetical ordering

- **WHEN** a name is built with several attribute types given out of
  alphabetical order
- **THEN** its rendering lists them alphabetically by attribute type

#### Scenario: An unknown attribute type

- **WHEN** a name is built with a keyword that is no X.509 attribute
  type
- **THEN** an error is raised naming that keyword

### Requirement: An attribute may carry several values

A value MAY be a sequence of strings instead of a single string. Each
value SHALL become its own attribute of that type, in the order
given, so a distinguished name can repeat an attribute type. This is
what a lossless distinguished-name parse must be tested against.

#### Scenario: Two organizational units

- **WHEN** a name is built with an organizational unit value of
  `["OU-A", "OU-B"]`
- **THEN** the resulting X.509 name carries two organizational unit
  attributes
- **AND** their values are `OU-A` then `OU-B`, in that order

#### Scenario: Order within a key is the caller's

- **WHEN** the same name is built with the two values reversed
- **THEN** the resulting attributes are reversed too

#### Scenario: Mixed single and multiple values

- **WHEN** a name is built with a single common name and a
  multi-valued organizational unit
- **THEN** the common name appears once and the organizational unit
  appears once per value
- **AND** attribute types are still ordered alphabetically

#### Scenario: A single-element sequence

- **WHEN** a name is built with a value of `["only"]`
- **THEN** the resulting X.509 name carries one attribute of that
  type

### Requirement: Multi-valued attributes stay frozen and hashable

An instance SHALL remain immutable, hashable and comparable by
content whatever the shape of its values. A multi-valued attribute
SHALL read back as a tuple, and SHALL be rendered by `repr()` as the
sequence a caller would type.

#### Scenario: Hashing a multi-valued name

- **WHEN** two names are built with the same multi-valued attribute
- **THEN** they compare equal and hash equal
- **AND** a set of both holds one element

#### Scenario: Reading a multi-valued attribute back

- **WHEN** a multi-valued organizational unit is read from the
  instance
- **THEN** a tuple of its values is returned

#### Scenario: Rendering a multi-valued name

- **WHEN** `repr()` is taken of a name with a multi-valued attribute
- **THEN** that attribute is rendered as a list of quoted strings

### Requirement: Wrong-typed names are reported

Anything passed as a subject or issuer name that is not a name
attributes object SHALL raise a `TypeError` naming the type passed,
rather than failing inside certificate construction.

#### Scenario: A raw X.509 name

- **WHEN** a certificate is issued with a `cryptography` name object
  as its subject
- **THEN** a `TypeError` naming that type is raised

#### Scenario: A string

- **WHEN** a certificate signing request is built with a string as
  its subject
- **THEN** a `TypeError` naming `str` is raised
