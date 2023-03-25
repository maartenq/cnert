# Cnert - TLS Certificates for testing

Cnert is trying to be a simple API for creating TLS Certificates testing
purposes.

[cnert.CA][] makes CAs, intermediate CAs and [certificates][cnert._Cert] and
has several methods for introspection.

Cnert has currently pre-alpha development status and is not (fully) working.


## Usage

### Create a root CA

    >>> import cnert
    >>> ca = cnert.CA()

    >>> ca.is_root_ca
    True

    >>> ca.is_intermediate_ca
    False

    >>> ca.parent is None
    True

### Create an intermediate CA

    >>> intermediate = ca.issue_intermediate()
    >>> intermediate.is_intermediate_ca
    True

    >>> intermediate.is_root_ca
    False

    >>> intermediate.parent is ca
    True


###  Inspect the CA's certificate

    >>> ca.cert
    <cnert.Cert at 0x112a14c50>

    >>> ca.cert.subject_attrs
    NameAttrs(ORGANIZATION_NAME="Root CA")

    >>> ca.cert.ca.cert.issuer_attrs
    NameAttrs(ORGANIZATION_NAME="Root CA")

    >>> ca.cert.not_valid_before
    datetime.datetime(2023, 3, 24, 21, 27, 50, 579389

    >>> ca.cert.not_valid_after
    datetime.datetime(2023, 6, 23, 20, 20, 47, 999034)


###  Issue a cert from a CA

    >>> cert = ca.issue_cert()

    >>> cert.subject_attrs
    NameAttrs(COMMON_NAME="example.com")
