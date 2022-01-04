# tests/cnert/test_cli.py

import ipaddress
from typing import Dict

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ObjectIdentifier, extensions, general_name
from cryptography.x509.extensions import (
    ExtendedKeyUsage,
    KeyUsage,
    SubjectAlternativeName,
)
from cryptography.x509.oid import NameOID

from cnert.cert import (
    _add_ca_extension,
    _add_leaf_cert_extensions,
    _add_subject_alt_name_extension,
    _identity_string_to_x509,
    _idna_encode,
    _key_usage,
    _private_key,
    _private_key_pem,
    _x509_name,
)


@pytest.fixture
def default_name_attrs():
    return dict(
        BUSINESS_CATEGORY="Business Category",
        COMMON_NAME="Common Name",
        COUNTRY_NAME="US",
        DN_QUALIFIER="DN qualifier",
        DOMAIN_COMPONENT="Domain Component",
        EMAIL_ADDRESS="info@example.com",
        GENERATION_QUALIFIER="Generation Qualifier",
        GIVEN_NAME="Given Name",
        INN="INN",
        JURISDICTION_COUNTRY_NAME="US",
        JURISDICTION_LOCALITY_NAME="Jurisdiction Locality Name",
        JURISDICTION_STATE_OR_PROVINCE_NAME=(
            "Jurisdiction State or Province Name"
        ),
        LOCALITY_NAME="Locality Name",
        OGRN="OGRN",
        ORGANIZATIONAL_UNIT_NAME="Organizational unit_name",
        ORGANIZATION_NAME="Organization Name",
        POSTAL_ADDRESS="Postal Address",
        POSTAL_CODE="Postal Code",
        PSEUDONYM="Pseudonym",
        SERIAL_NUMBER="42",
        SNILS="SNILS",
        STATE_OR_PROVINCE_NAME="State or Province Name",
        STREET_ADDRESS="Street Address",
        SURNAME="Surname",
        TITLE="Title",
        UNSTRUCTURED_NAME="unstructuredName",
        USER_ID="User ID",
        X500_UNIQUE_IDENTIFIER="X500 Unique Identifier",
    )


def test__idna_encode():
    assert _idna_encode("*.example.com") == "*.example.com"
    assert _idna_encode("*.éxample.com") == "*.xn--xample-9ua.com"
    assert _idna_encode("Example.com") == "example.com"


def test__identity_string_to_x509_IPAddress():
    x509_IP = _identity_string_to_x509("198.51.100.1")
    assert type(x509_IP) is general_name.IPAddress
    assert x509_IP.value == ipaddress.IPv4Address("198.51.100.1")


def test__identity_string_to_x509_NetWork():
    x509_network = _identity_string_to_x509("198.51.100.0/24")
    assert type(x509_network) is general_name.IPAddress
    assert x509_network.value == ipaddress.IPv4Network("198.51.100.0/24")


def test__identity_string_to_x509_RFC822Name():
    x509_email_addr = _identity_string_to_x509("harry@example.com")
    assert type(x509_email_addr) is general_name.RFC822Name
    assert x509_email_addr.value == "harry@example.com"


def test__identity_string_to_x509_DNSName():
    x509_dns_name = _identity_string_to_x509("host.example.com")
    assert type(x509_dns_name) is general_name.DNSName
    assert x509_dns_name.value == "host.example.com"


def test__private_key():
    private_key = _private_key()
    assert private_key.key_size == 2048


def test__private_key_pem():
    pem = _private_key_pem(
        rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
    )
    assert b"-----BEGIN RSA PRIVATE KEY-----" in pem
    assert b"-----END RSA PRIVATE KEY-----" in pem


def test__key_usage_defaults():
    key_usage = _key_usage()
    assert type(key_usage) is extensions.KeyUsage
    assert key_usage.content_commitment is False
    assert key_usage.crl_sign is False
    assert key_usage.data_encipherment is False
    assert key_usage.digital_signature is True
    # assert key_usage.decipher_only is False
    # assert key_usage.encipher_only is False
    assert key_usage.key_agreement is False
    assert key_usage.key_cert_sign is False
    assert key_usage.key_encipherment is True


def test__key_usage_ca():
    key_usage = _key_usage(
        digital_signature=True,
        key_cert_sign=True,
        crl_sign=True,
    )
    assert type(key_usage) is extensions.KeyUsage
    assert key_usage.content_commitment is False
    assert key_usage.crl_sign is True
    assert key_usage.data_encipherment is False
    assert key_usage.digital_signature is True
    # assert key_usage.decipher_only is False
    # assert key_usage.encipher_only is False
    assert key_usage.key_agreement is False
    assert key_usage.key_cert_sign is True
    assert key_usage.key_encipherment is True


def test_X509Name_default(default_name_attrs):
    assert _x509_name() == x509.Name(
        [
            x509.NameAttribute(getattr(NameOID, key), value)
            for (key, value) in default_name_attrs.items()
        ]
    )


def test_X509Name_with_key_arguments():
    NAME_ATTRS: Dict[str, str] = dict(
        COMMON_NAME="Jansen",
        COUNTRY_NAME="NL",
        EMAIL_ADDRESS="harry@example.com",
        GIVEN_NAME="Harry de Groot",
    )
    assert _x509_name(**NAME_ATTRS) == x509.Name(
        [
            x509.NameAttribute(getattr(NameOID, key), value)
            for (key, value) in NAME_ATTRS.items()
        ]
    )


def test_X509Name_with_lower_key_arguments():
    NAME_ATTRS: Dict[str, str] = dict(
        common_name="Jansen",
        country_name="NL",
        email_address="harry@example.com",
        given_name="Harry de Groot",
    )
    assert _x509_name(**NAME_ATTRS) == x509.Name(
        [
            x509.NameAttribute(getattr(NameOID, key.upper()), value)
            for (key, value) in NAME_ATTRS.items()
        ]
    )


def test_X509Name_raises_exception():
    with pytest.raises(AttributeError):
        _x509_name(NON_EXISTING_NAME_ATTR="should not exist")


def test__add_ca_extention():
    builder = _add_ca_extension(x509.CertificateBuilder())
    key_usage = builder._extensions[0].value
    assert type(key_usage) is extensions.KeyUsage
    assert key_usage.content_commitment is False
    assert key_usage.crl_sign is True
    assert key_usage.data_encipherment is False
    assert key_usage.digital_signature is True
    # assert key_usage.decipher_only is False
    # assert key_usage.encipher_only is False
    assert key_usage.key_agreement is False
    assert key_usage.key_cert_sign is True
    assert key_usage.key_encipherment is True


def test__add_leaf_cert_extensions_key_usage():
    builder = _add_leaf_cert_extensions(x509.CertificateBuilder())
    key_usage = builder._extensions[0].value
    assert type(key_usage) is KeyUsage
    assert key_usage.content_commitment is False
    assert key_usage.crl_sign is False
    assert key_usage.data_encipherment is False
    assert key_usage.digital_signature is True
    # assert key_usage.decipher_only is False
    # assert key_usage.encipher_only is False
    assert key_usage.key_agreement is False
    assert key_usage.key_cert_sign is False
    assert key_usage.key_encipherment is True


def test__add_leaf_cert_extensions_extended_key_usage():
    builder = _add_leaf_cert_extensions(x509.CertificateBuilder())
    ext_key_usage = builder._extensions[1].value
    assert type(ext_key_usage) is ExtendedKeyUsage
    assert list(ext_key_usage) == [
        ObjectIdentifier("1.3.6.1.5.5.7.3.2"),
        ObjectIdentifier("1.3.6.1.5.5.7.3.1"),
        ObjectIdentifier("1.3.6.1.5.5.7.3.3"),
    ]


def test__add_subject_alt_name_extension():
    hostnames = [
        "host1.example.com",
        "host2.example.com",
    ]
    builder = _add_subject_alt_name_extension(
        x509.CertificateBuilder(),
        *hostnames,
    )
    ext_alt_name = builder._extensions[0].value
    assert type(ext_alt_name) is SubjectAlternativeName
    assert list(ext_alt_name) == [
        general_name.DNSName(hostname) for hostname in hostnames
    ]
