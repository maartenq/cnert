# tests/cnert/test_cli.py

from __future__ import annotations  # for Python 3.7-3.9

import datetime
import ipaddress
import re

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed448,
    ed25519,
    rsa,
)
from cryptography.x509 import ObjectIdentifier, extensions, general_name
from cryptography.x509.oid import NameOID

import cnert


@pytest.fixture
def default_name_attrs():
    return {
        "BUSINESS_CATEGORY": "business category",
        "COMMON_NAME": "common name",
        "COUNTRY_NAME": "AQ",
        "DN_QUALIFIER": "DN qualifier",
        "DOMAIN_COMPONENT": "domain component",
        "EMAIL_ADDRESS": "example@example.com",
        "GENERATION_QUALIFIER": "generation qualifier",
        "GIVEN_NAME": "given name",
        "INN": "INN",
        "JURISDICTION_COUNTRY_NAME": "AQ",
        "JURISDICTION_LOCALITY_NAME": "jurisdiction locality Name",
        "JURISDICTION_STATE_OR_PROVINCE_NAME": (
            "jurisdiction state or province name"
        ),
        "LOCALITY_NAME": "locality name",
        "OGRN": "OGRN",
        "ORGANIZATIONAL_UNIT_NAME": "organizational unit_name",
        "ORGANIZATION_NAME": "organization name",
        "POSTAL_ADDRESS": "postal address",
        "POSTAL_CODE": "postal code",
        "PSEUDONYM": "pseudonym",
        "SERIAL_NUMBER": "42",
        "SNILS": "SNILS",
        "STATE_OR_PROVINCE_NAME": "state or province name",
        "STREET_ADDRESS": "street address",
        "SURNAME": "surname",
        "TITLE": "title",
        "UNSTRUCTURED_NAME": "unstructuredName",
        "USER_ID": "user ID",
        "X500_UNIQUE_IDENTIFIER": "X500 unique identifier",
    }


@pytest.fixture
def private_key():
    return rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )


@pytest.fixture
def public_key(private_key):
    return private_key.public_key()


@pytest.fixture
def csr(private_key):
    name = "example.com"
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name)]),
            critical=False,
        )
        .sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
    )


@pytest.fixture
def ca_cert():
    return cnert.CA().cert


@pytest.fixture
def cert():
    return cnert.CA().issue_cert()


@pytest.mark.parametrize(
    "test_input,expected",
    [
        ("*.example.com", "*.example.com"),
        ("*.éxample.com", "*.xn--xample-9ua.com"),
        ("Example.com", "example.com"),
    ],
)
def test_idna_encode(test_input, expected):
    assert cnert.idna_encode(test_input) == expected


def test_identity_string_to_x509_IPAddress():
    x509_network = cnert.identity_string_to_x509("198.51.100.1")
    assert type(x509_network) is general_name.IPAddress
    assert x509_network.value == ipaddress.IPv4Address("198.51.100.1")


def test_identity_string_to_x509_NetWork():
    x509_network = cnert.identity_string_to_x509("198.51.100.0/24")
    assert type(x509_network) is general_name.IPAddress
    assert x509_network.value == ipaddress.IPv4Network("198.51.100.0/24")


def test_dentity_string_to_x509_RFC822Name():
    x509_email_addr = cnert.identity_string_to_x509("harry@example.com")
    assert type(x509_email_addr) is general_name.RFC822Name
    assert x509_email_addr.value == "harry@example.com"


def test_identity_string_to_x509_DNSName():
    x509_dns_name = cnert.identity_string_to_x509("host.example.com")
    assert type(x509_dns_name) is general_name.DNSName
    assert x509_dns_name.value == "host.example.com"


def test_frozen_attrs_change_attr():
    class Frozen(cnert.Freezer):
        def __init__(self, slot1):
            self.slot1 = slot1
            super().__init__()

    frozen = Frozen(slot1="frozen")
    with pytest.raises(Exception) as exc:
        frozen.slot1 = "not allowed"
    assert exc.type is AttributeError
    assert "This object is frozen!" in str(exc.value)


def test_frozen_attrs_add_attr():
    class Frozen(cnert.Freezer):
        def __init__(self, slot1):
            self.slot1 = slot1
            super().__init__()

    frozen = Frozen(slot1="frozen")
    with pytest.raises(Exception) as exc:
        frozen.slot2 = "not allowed"
    assert exc.type is AttributeError
    assert "This object is frozen!" in str(exc.value)


def test_frozen_attrs_del_attr_allowed():
    class Frozen(cnert.Freezer):
        def __init__(self, slot1):
            self.slot1 = slot1

    frozen = Frozen(slot1="frozen")
    del frozen.slot1


def test_frozen_attrs_del_attr():
    class Frozen(cnert.Freezer):
        def __init__(self, slot1):
            self.slot1 = slot1
            super().__init__()

    frozen = Frozen(slot1="frozen")
    with pytest.raises(Exception) as exc:
        del frozen.slot1
    assert exc.type is AttributeError
    assert "This object is frozen!" in str(exc.value)


def test_name_attrs__repr__with_default_name_attrs_names(default_name_attrs):
    name_attrs = cnert.NameAttrs(**default_name_attrs)
    assert (
        repr(name_attrs) == "NameAttrs("
        'BUSINESS_CATEGORY="business category", '
        'COMMON_NAME="common name", '
        'COUNTRY_NAME="AQ", '
        'DN_QUALIFIER="DN qualifier", '
        'DOMAIN_COMPONENT="domain component", '
        'EMAIL_ADDRESS="example@example.com", '
        'GENERATION_QUALIFIER="generation qualifier", '
        'GIVEN_NAME="given name", '
        'INN="INN", '
        'JURISDICTION_COUNTRY_NAME="AQ", '
        'JURISDICTION_LOCALITY_NAME="jurisdiction locality Name", '
        "JURISDICTION_STATE_OR_PROVINCE_NAME="
        '"jurisdiction state or province name", '
        'LOCALITY_NAME="locality name", '
        'OGRN="OGRN", '
        'ORGANIZATIONAL_UNIT_NAME="organizational unit_name", '
        'ORGANIZATION_NAME="organization name", '
        'POSTAL_ADDRESS="postal address", '
        'POSTAL_CODE="postal code", '
        'PSEUDONYM="pseudonym", '
        'SERIAL_NUMBER="42", '
        'SNILS="SNILS", '
        'STATE_OR_PROVINCE_NAME="state or province name", '
        'STREET_ADDRESS="street address", '
        'SURNAME="surname", '
        'TITLE="title", '
        'UNSTRUCTURED_NAME="unstructuredName", '
        'USER_ID="user ID", '
        'X500_UNIQUE_IDENTIFIER="X500 unique identifier"'
        ")"
    )


def test_name_attrs__repr__is_alphabetically_ordered():
    name_attrs = cnert.NameAttrs(
        COMMON_NAME="example.com",
        STREET_ADDRESS="Getreidegasse 9",
        LOCALITY_NAME="Salzburg",
        COUNTRY_NAME="AT",
        EMAIL_ADDRESS="info@example.com",
    )

    assert (
        repr(name_attrs)
        == 'NameAttrs(COMMON_NAME="example.com", COUNTRY_NAME="AT", '
        'EMAIL_ADDRESS="info@example.com", LOCALITY_NAME="Salzburg", '
        'STREET_ADDRESS="Getreidegasse 9")'
    )


def test_name_attrs__str__with_default_name_attrs_names(default_name_attrs):
    name_attrs = cnert.NameAttrs(**default_name_attrs)
    assert (
        str(name_attrs) == "2.5.4.45=X500 unique identifier,"
        "UID=user ID,"
        "1.2.840.113549.1.9.2=unstructuredName,"
        "2.5.4.12=title,"
        "2.5.4.4=surname,"
        "STREET=street address,"
        "ST=state or province name,"
        "1.2.643.100.3=SNILS,"
        "2.5.4.5=42,"
        "2.5.4.65=pseudonym,"
        "2.5.4.17=postal code,"
        "2.5.4.16=postal address,"
        "O=organization name,"
        "OU=organizational unit_name,"
        "1.2.643.100.1=OGRN,"
        "L=locality name,"
        "1.3.6.1.4.1.311.60.2.1.2=jurisdiction state or province name,"
        "1.3.6.1.4.1.311.60.2.1.1=jurisdiction locality Name,"
        "1.3.6.1.4.1.311.60.2.1.3=AQ,"
        "1.2.643.3.131.1.1=INN,"
        "2.5.4.42=given name,"
        "2.5.4.44=generation qualifier,"
        "1.2.840.113549.1.9.1=example@example.com,"
        "DC=domain component,"
        "2.5.4.46=DN qualifier,"
        "C=AQ,"
        "CN=common name,"
        "2.5.4.15=business category"
    )


def test_name_attrs__str__is_reversed_alphabetically_ordered():
    name_attrs = cnert.NameAttrs(
        COMMON_NAME="example.com",
        STREET_ADDRESS="Getreidegasse 9",
        LOCALITY_NAME="Salzburg",
        COUNTRY_NAME="AT",
        EMAIL_ADDRESS="info@example.com",
    )

    assert (
        str(name_attrs) == "STREET=Getreidegasse 9,"
        "L=Salzburg,"
        "1.2.840.113549.1.9.1=info@example.com,"
        "C=AT,"
        "CN=example.com"
    )


def test_name_attrs_are_valid(default_name_attrs):
    name_attrs = cnert.NameAttrs(**default_name_attrs)
    for key, value in default_name_attrs.items():
        assert getattr(name_attrs, key) == value


def test_name_attr_invalid():
    with pytest.raises(Exception) as exc:
        cnert.NameAttrs(INVALID_X509_NAME_ATTR="any value")
    assert exc.type is AttributeError
    assert (
        "type object 'NameOID' has no attribute 'INVALID_X509_NAME_ATTR'"
        in str(exc.value)
    )


def test_name_attrs_list():
    name_attrs = cnert.NameAttrs()
    assert name_attrs.allowed_keys() == [
        "BUSINESS_CATEGORY",
        "COMMON_NAME",
        "COUNTRY_NAME",
        "DN_QUALIFIER",
        "DOMAIN_COMPONENT",
        "EMAIL_ADDRESS",
        "GENERATION_QUALIFIER",
        "GIVEN_NAME",
        "INN",
        "JURISDICTION_COUNTRY_NAME",
        "JURISDICTION_LOCALITY_NAME",
        "JURISDICTION_STATE_OR_PROVINCE_NAME",
        "LOCALITY_NAME",
        "OGRN",
        "ORGANIZATIONAL_UNIT_NAME",
        "ORGANIZATION_NAME",
        "POSTAL_ADDRESS",
        "POSTAL_CODE",
        "PSEUDONYM",
        "SERIAL_NUMBER",
        "SNILS",
        "STATE_OR_PROVINCE_NAME",
        "STREET_ADDRESS",
        "SURNAME",
        "TITLE",
        "UNSTRUCTURED_NAME",
        "USER_ID",
        "X500_UNIQUE_IDENTIFIER",
    ]


def test_name_attr_x509():
    name_attrs = cnert.NameAttrs(COMMON_NAME="my common name")
    assert name_attrs.x509_name() == x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "my common name")]
    )


def test_name_attr_x509_str():
    name_attrs = cnert.NameAttrs(COMMON_NAME="my common name")
    assert str(name_attrs) == "CN=my common name"


def test_CA__str__():
    ca = cnert.CA()
    assert str(ca) == "CA O=Root CA"


def test_CA_is_root_ca_not_intemediate():
    ca = cnert.CA()
    assert ca.is_root_ca
    assert not ca.is_intermediate_ca


def test_CA_parent_is_none():
    ca = cnert.CA()
    assert ca.parent is None


def test_intermediate_is_intermediate_ca_not_ca():
    ca = cnert.CA()
    intermediate = ca.issue_intermediate()
    assert intermediate.is_intermediate_ca
    assert not intermediate.is_root_ca


def test_intermediate_parent_is_ca():
    ca = cnert.CA()
    intermediate = ca.issue_intermediate()
    assert intermediate.parent is ca


def test_CA_default_name_attr_common_name():
    ca = cnert.CA()
    assert ca.cert.subject_attrs.ORGANIZATION_NAME == "Root CA"


def test_CA_subject_attrs_is_issue_attrs():
    ca = cnert.CA()
    assert ca.cert.subject_attrs == ca.cert.issuer_attrs


def test_CA_serial_number_is_44():
    ca = cnert.CA(serial_number=44)
    assert ca.cert.serial_number == 44


def test_CA_issue_intermediate_first():
    ca = cnert.CA()
    intermediate_1 = ca.issue_intermediate()
    assert (
        intermediate_1.cert.subject_attrs.ORGANIZATION_NAME
        == "CA Intermediate 1"
    )
    assert intermediate_1.cert.path_length == 8


def test_CA_issue_intermediate_second():
    ca = cnert.CA()
    intermediate_1 = ca.issue_intermediate()
    intermediate_2 = intermediate_1.issue_intermediate()
    assert (
        intermediate_2.cert.subject_attrs.ORGANIZATION_NAME
        == "CA Intermediate 2"
    )
    assert intermediate_2.cert.path_length == 7


def test_CA_issue_intermediate_third():
    ca = cnert.CA()
    intermediate_1 = ca.issue_intermediate()
    intermediate_2 = intermediate_1.issue_intermediate()
    intermediate_3 = intermediate_2.issue_intermediate()
    assert (
        intermediate_3.cert.subject_attrs.ORGANIZATION_NAME
        == "CA Intermediate 3"
    )
    assert intermediate_3.cert.path_length == 6


def test_CA_issue_intermediate_max_path_lenght():
    ca = cnert.CA(path_length=2)
    intermediate_1 = ca.issue_intermediate()
    intermediate_2 = intermediate_1.issue_intermediate()
    with pytest.raises(Exception) as exc:
        intermediate_2.issue_intermediate()
    assert exc.type is ValueError
    assert "Can't create intermediate CA: path length is 0" in str(exc.value)


def test_CA_issue_intermediate_serial_number_is_13():
    ca = cnert.CA()
    im = ca.issue_intermediate(serial_number=13)
    assert im.cert.serial_number == 13


def test_CA_issue_cert_default_common_name_is_example_com():
    ca = cnert.CA()
    cert = ca.issue_cert()
    assert cert.subject_attrs.COMMON_NAME == "example.com"


def test_CA_issue_cert_default_common_name_is_www_example_com():
    ca = cnert.CA()
    subject_attrs = cnert.NameAttrs(COMMON_NAME="www.example.com")
    cert = ca.issue_cert(subject_attrs=subject_attrs)
    assert cert.subject_attrs.COMMON_NAME == "www.example.com"


def test_CA_issue_cert_sans():
    ca = cnert.CA()
    sans = ("www.example.com", "example.com")
    cert = ca.issue_cert(*sans)
    assert cert.subject_attrs.COMMON_NAME == "www.example.com"


def test_CA_issue_cert_serial_number_is_43():
    ca = cnert.CA()
    cert = ca.issue_cert(serial_number=43)
    assert cert.serial_number == 43


def test_CA_issue_cert_with_csr(mocker, private_key):
    sans = ("www.example.com", "example.com")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="www.example.com")
    mock_CSR = mocker.patch("cnert.CSR")
    mock_CSR.return_value.sans = sans
    mock_CSR.return_value.subject_attrs = subject_attrs
    mock_CSR.return_value.private_key = private_key
    csr = cnert.CSR()
    ca = cnert.CA()
    cert = ca.issue_cert(csr=csr)
    assert cert.subject_attrs.COMMON_NAME == "www.example.com"
    assert cert.sans == sans
    assert cert.private_key == private_key


def test__Cert__str__():
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(
        COMMON_NAME="www.example.com",
        COUNTRY_NAME="AQ",
        ORGANIZATION_NAME="Acme",
    )
    cert = cnert.Cert(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
    assert str(cert) == "Certificate O=Acme,C=AQ,CN=www.example.com"


def test__Cert_default_not_valid_before():
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    before = datetime.datetime.now(datetime.UTC)
    cert = cnert.Cert(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
    assert cert.not_valid_before - before < datetime.timedelta(minutes=1)


def test__Cert_default_not_valid_after():
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    after = datetime.datetime.now(datetime.UTC) + datetime.timedelta(weeks=13)
    cert = cnert.Cert(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
    assert cert.not_valid_after - after < datetime.timedelta(minutes=1)


def test__Cert_private_key_size():
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    cert = cnert.Cert(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
    assert cert.private_key.key_size == 2048


def test__Cert_private_key_pem_PKCS1():
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    cert = cnert.Cert(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
    assert cert.private_key_pem_PKCS1.startswith(
        b"-----BEGIN RSA PRIVATE KEY-----\n"
    )
    assert cert.private_key_pem_PKCS1.endswith(
        b"\n-----END RSA PRIVATE KEY-----\n"
    )


def test__Cert_private_key_pem_with_given_private_key(private_key):
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    cert = cnert.Cert(
        subject_attrs=subject_attrs,
        issuer_attrs=issuer_attrs,
        private_key=private_key,
    )
    assert cert.private_key_pem_PKCS8.startswith(
        b"-----BEGIN PRIVATE KEY-----\n"
    )
    assert cert.private_key_pem_PKCS8.endswith(
        b"\n-----END PRIVATE KEY-----\n"
    )


def test__Cert_private_key_size_with_given_private_key(private_key):
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    cert = cnert.Cert(
        subject_attrs=subject_attrs,
        issuer_attrs=issuer_attrs,
        private_key=private_key,
    )
    assert cert.private_key.key_size == 2048


def test__Cert_private_key_pem_PKCS1_with_given_private_key(private_key):
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    cert = cnert.Cert(
        subject_attrs=subject_attrs,
        issuer_attrs=issuer_attrs,
        private_key=private_key,
    )
    assert cert.private_key_pem_PKCS1.startswith(
        b"-----BEGIN RSA PRIVATE KEY-----\n"
    )
    assert cert.private_key_pem_PKCS1.endswith(
        b"\n-----END RSA PRIVATE KEY-----\n"
    )


def test__Cert_private_key_pem_PKCS8():
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    cert = cnert.Cert(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
    assert cert.private_key_pem_PKCS8.startswith(
        b"-----BEGIN PRIVATE KEY-----\n"
    )
    assert cert.private_key_pem_PKCS8.endswith(
        b"\n-----END PRIVATE KEY-----\n"
    )


def test__Cert_public_key_pem_PKCS1():
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    cert = cnert.Cert(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
    assert cert.public_key_pem.startswith(b"-----BEGIN PUBLIC KEY-----\n")
    assert cert.public_key_pem.endswith(b"\n-----END PUBLIC KEY-----\n")


def test__Cert_public_key():
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    cert = cnert.Cert(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
    assert isinstance(cert.public_key, rsa.RSAPublicKey)


def test__Cert_serialnumber_is_42():
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    cert = cnert.Cert(
        subject_attrs=subject_attrs,
        issuer_attrs=issuer_attrs,
        serial_number=42,
    )
    assert cert.serial_number == 42


def test__Cert_MD5(cert):
    assert re.match("^[A-F0-9]{32}$", cert.MD5)


def test__Cert_SHA1(cert):
    assert re.match("^[A-F0-9]{40}$", cert.SHA1)


def test__Cert_SHA246(cert):
    assert re.match("^[A-F0-9]{64}$", cert.SHA256)


def test__Cert_subject_key_identifier_digest(cert):
    assert re.match("^[A-F0-9]{40}$", cert.subject_key_identifier_digest)


def test__Cert_authority_key_identifier_digest(cert):
    assert re.match("^[A-F0-9]{40}$", cert.authority_key_identifier_digest)


def test__Cert_authority_key_identifier_digest_is_None_for_ca_cert(ca_cert):
    assert ca_cert.authority_key_identifier_digest is None


def test__Cert_serialnumber_is_random():
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    cert1 = cnert.Cert(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
    cert2 = cnert.Cert(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
    assert cert1.serial_number != cert2.serial_number


def test__CertBuilder__key_usage_defaults():
    builder = cnert._CertBuilder()
    key_usage = builder._key_usage()
    assert type(key_usage) is extensions.KeyUsage
    assert key_usage.content_commitment is False
    assert key_usage.crl_sign is False
    assert key_usage.data_encipherment is False
    assert key_usage.digital_signature is True
    assert key_usage.key_agreement is False
    assert key_usage.key_cert_sign is False
    assert key_usage.key_encipherment is True


def test__CertBuilder__key_usage_ca():
    builder = cnert._CertBuilder()
    key_usage = builder._key_usage(
        digital_signature=True,
        key_cert_sign=True,
        crl_sign=True,
    )
    assert type(key_usage) is extensions.KeyUsage
    assert key_usage.content_commitment is False
    assert key_usage.crl_sign is True
    assert key_usage.data_encipherment is False
    assert key_usage.digital_signature is True
    assert key_usage.key_agreement is False
    assert key_usage.key_cert_sign is True
    assert key_usage.key_encipherment is True


def test__CertBuilder_ca_extensions():
    pairs = cnert._CertBuilder()._ca_extensions()
    assert len(pairs) == 1
    key_usage, critical = pairs[0]
    assert critical is True
    assert type(key_usage) is extensions.KeyUsage
    assert key_usage.oid.dotted_string == "2.5.29.15"
    assert key_usage.content_commitment is False
    assert key_usage.crl_sign is True
    assert key_usage.data_encipherment is False
    assert key_usage.digital_signature is True
    assert key_usage.key_agreement is False
    assert key_usage.key_cert_sign is True
    assert key_usage.key_encipherment is True


def test__CertBuilder_leaf_cert_extensions_key_usage():
    pairs = cnert._CertBuilder()._leaf_cert_extensions()
    assert len(pairs) == 2
    key_usage, critical = pairs[0]
    assert critical is True
    assert type(key_usage) is extensions.KeyUsage
    assert key_usage.oid.dotted_string == "2.5.29.15"
    assert key_usage.content_commitment is False
    assert key_usage.crl_sign is False
    assert key_usage.data_encipherment is False
    assert key_usage.digital_signature is True
    assert key_usage.key_agreement is False
    assert key_usage.key_cert_sign is False
    assert key_usage.key_encipherment is True


def test__CertBuilder_leaf_cert_extensions_extended_key_usage():
    extended_key_usage, critical = (
        cnert._CertBuilder()._leaf_cert_extensions()[1]
    )
    assert critical is True
    assert type(extended_key_usage) is extensions.ExtendedKeyUsage
    assert extended_key_usage.oid.dotted_string == "2.5.29.37"
    assert list(extended_key_usage) == [
        ObjectIdentifier("1.3.6.1.5.5.7.3.2"),
        ObjectIdentifier("1.3.6.1.5.5.7.3.1"),
        ObjectIdentifier("1.3.6.1.5.5.7.3.3"),
    ]


def test__CertBuilder_authority_key_identifier_extension(public_key):
    extension, critical = (
        cnert._CertBuilder()._authority_key_identifier_extension(public_key)
    )
    assert critical is False
    assert type(extension) is extensions.AuthorityKeyIdentifier
    assert extension.oid.dotted_string == "2.5.29.35"


def test__CertBuilder_subject_alt_name_extension():
    sans = (
        "host1.example.com",
        "host2.example.com",
    )
    sub_alt_name, critical = cnert._CertBuilder()._subject_alt_name_extension(
        *sans
    )
    assert critical is True
    assert sub_alt_name.oid.dotted_string == "2.5.29.17"
    assert type(sub_alt_name) is extensions.SubjectAlternativeName
    assert list(sub_alt_name) == [general_name.DNSName(san) for san in sans]


def test__CertBuilder_build(public_key):
    cert_builder = cnert._CertBuilder()
    cert_builder.build(
        sans=(),
        subject_attrs_X509_name=x509.Name(
            [x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CA")]
        ),
        issuer_attrs_X509_name=x509.Name(
            [x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CA")]
        ),
        serial_number=1,
        not_valid_before=datetime.datetime.now(datetime.UTC),
        not_valid_after=datetime.datetime.now(datetime.UTC)
        + datetime.timedelta(days=13),
        is_ca=True,
        public_key=public_key,
        path_length=8,
    )
    assert len(cert_builder.builder._extensions) == 3
    sub_key_id = cert_builder.builder._extensions[0]
    assert sub_key_id.oid.dotted_string == "2.5.29.14"
    assert type(sub_key_id.value) is extensions.SubjectKeyIdentifier
    assert (
        sub_key_id.value.digest
        == x509.SubjectKeyIdentifier.from_public_key(public_key).digest
    )
    basic_constraints = cert_builder.builder._extensions[1]
    assert basic_constraints.oid.dotted_string == "2.5.29.19"
    assert type(basic_constraints.value) is extensions.BasicConstraints
    assert basic_constraints.value.ca is True
    assert basic_constraints.value.path_length == 8
    key_usage = cert_builder.builder._extensions[2]
    assert type(key_usage.value) is extensions.KeyUsage
    assert key_usage.oid.dotted_string == "2.5.29.15"
    assert key_usage.value.content_commitment is False
    assert key_usage.value.crl_sign is True
    assert key_usage.value.data_encipherment is False
    assert key_usage.value.digital_signature is True
    assert key_usage.value.key_agreement is False
    assert key_usage.value.key_cert_sign is True
    assert key_usage.value.key_encipherment is True


def test__CertBuilder_build_with_san(public_key):
    sans = ("example.com", "www.example.com")
    cert_builder = cnert._CertBuilder()
    cert_builder.build(
        sans=sans,
        subject_attrs_X509_name=x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]
        ),
        issuer_attrs_X509_name=x509.Name(
            [x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CA")]
        ),
        serial_number=1,
        not_valid_before=datetime.datetime.now(datetime.UTC),
        not_valid_after=datetime.datetime.now(datetime.UTC)
        + datetime.timedelta(days=13),
        is_ca=True,
        path_length=8,
        public_key=public_key,
    )
    assert len(cert_builder.builder._extensions) == 4
    sub_key_id = cert_builder.builder._extensions[0]
    assert sub_key_id.oid.dotted_string == "2.5.29.14"
    assert type(sub_key_id.value) is extensions.SubjectKeyIdentifier
    assert (
        sub_key_id.value.digest
        == x509.SubjectKeyIdentifier.from_public_key(public_key).digest
    )
    basic_constraints = cert_builder.builder._extensions[1]
    assert basic_constraints.oid.dotted_string == "2.5.29.19"
    assert type(basic_constraints.value) is extensions.BasicConstraints
    assert basic_constraints.value.ca is True
    assert basic_constraints.value.path_length == 8
    key_usage = cert_builder.builder._extensions[2]
    assert type(key_usage.value) is extensions.KeyUsage
    assert key_usage.oid.dotted_string == "2.5.29.15"
    assert key_usage.value.content_commitment is False
    assert key_usage.value.crl_sign is True
    assert key_usage.value.data_encipherment is False
    assert key_usage.value.digital_signature is True
    assert key_usage.value.key_agreement is False
    assert key_usage.value.key_cert_sign is True
    assert key_usage.value.key_encipherment is True
    sub_alt_name = cert_builder.builder._extensions[3]
    assert sub_alt_name.oid.dotted_string == "2.5.29.17"
    assert type(sub_alt_name.value) is extensions.SubjectAlternativeName
    assert list(sub_alt_name.value) == [
        general_name.DNSName(san) for san in sans
    ]


def test_CSR_default_common_name_is_example_com():
    csr = cnert.CSR()
    assert csr.subject_attrs.COMMON_NAME == "example.com"


def test_CSR_default_common_name_is_www_example_com():
    subject_attrs = cnert.NameAttrs(COMMON_NAME="www.example.com")
    csr = cnert.CSR(subject_attrs=subject_attrs)
    assert csr.subject_attrs.COMMON_NAME == "www.example.com"


def test_CSR_sans():
    sans = ("www.example.com", "example.com")
    csr = cnert.CSR(*sans)
    assert csr.subject_attrs.COMMON_NAME == "www.example.com"


def test_CSR_default_common_name_is_example_com_with_given_private_key(
    private_key,
):
    csr = cnert.CSR(private_key=private_key)
    assert csr.subject_attrs.COMMON_NAME == "example.com"


def test_CSR__str__():
    subject_attrs = cnert.NameAttrs(
        COMMON_NAME="www.example.com",
        COUNTRY_NAME="AQ",
        ORGANIZATION_NAME="Acme",
    )
    csr = cnert.CSR(subject_attrs=subject_attrs)
    assert str(csr) == "Certificate O=Acme,C=AQ,CN=www.example.com"


def test_CSR_private_key_size():
    csr = cnert.CSR()
    assert csr.private_key.key_size == 2048


def test_CSR_private_key_size_with_given_private_key(private_key):
    csr = cnert.CSR(private_key=private_key)
    assert csr.private_key.key_size == 2048


def test_CSR_private_key_pem_PKCS1():
    csr = cnert.CSR()
    assert csr.private_key_pem_PKCS1.startswith(
        b"-----BEGIN RSA PRIVATE KEY-----\n"
    )
    assert csr.private_key_pem_PKCS1.endswith(
        b"\n-----END RSA PRIVATE KEY-----\n"
    )


def test__CSR_private_key_pem_PKCS8():
    csr = cnert.CSR()
    assert csr.private_key_pem_PKCS8.startswith(
        b"-----BEGIN PRIVATE KEY-----\n"
    )
    assert csr.private_key_pem_PKCS8.endswith(b"\n-----END PRIVATE KEY-----\n")


def test_CSR_public_key():
    csr = cnert.CSR()
    assert isinstance(csr.public_key, rsa.RSAPublicKey)


def test_name_attrs_eq_other_type_is_not_implemented():
    assert cnert.NameAttrs(COMMON_NAME="example.com") != "example.com"


def test_name_attrs_is_hashable():
    a = cnert.NameAttrs(COMMON_NAME="example.com")
    b = cnert.NameAttrs(COMMON_NAME="example.com")
    assert hash(a) == hash(b)
    assert len({a, b}) == 1


def test_cert_deprecated_alias():
    assert cnert._Cert is cnert.Cert


@pytest.mark.parametrize(
    "algorithm,key_type",
    [
        ("rsa", rsa.RSAPrivateKey),
        ("ed25519", ed25519.Ed25519PrivateKey),
        ("ed448", ed448.Ed448PrivateKey),
        ("secp256r1", ec.EllipticCurvePrivateKey),
        ("secp384r1", ec.EllipticCurvePrivateKey),
        ("secp521r1", ec.EllipticCurvePrivateKey),
    ],
)
def test_build_private_key_algorithm(algorithm, key_type):
    assert isinstance(cnert.build_private_key(algorithm=algorithm), key_type)


@pytest.mark.parametrize(
    "algorithm,curve_name",
    [
        ("secp256r1", "secp256r1"),
        ("secp384r1", "secp384r1"),
        ("secp521r1", "secp521r1"),
    ],
)
def test_build_private_key_curve(algorithm, curve_name):
    key = cnert.build_private_key(algorithm=algorithm)
    assert key.curve.name == curve_name


def test_build_private_key_default_is_rsa_2048():
    key = cnert.build_private_key()
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 2048
    assert key.public_key().public_numbers().e == 65537


def test_build_private_key_rsa_sizing():
    key = cnert.build_private_key(key_size=1024, public_exponent=3)
    assert key.key_size == 1024
    assert key.public_key().public_numbers().e == 3


def test_build_private_key_unknown_algorithm():
    with pytest.raises(ValueError, match="unknown algorithm 'secp256k1'"):
        cnert.build_private_key(algorithm="secp256k1")


def test_build_private_key_unknown_algorithm_lists_names():
    with pytest.raises(ValueError, match="rsa, ed25519, ed448, secp256r1"):
        cnert.build_private_key(algorithm="nope")


@pytest.mark.parametrize(
    "kwargs",
    [{"key_size": 1024}, {"public_exponent": 3}],
)
def test_build_private_key_rsa_only_arguments(kwargs):
    with pytest.raises(ValueError, match="RSA-only"):
        cnert.build_private_key(algorithm="ed25519", **kwargs)


def test_KEY_ALGORITHMS():
    assert cnert.KEY_ALGORITHMS == (
        "rsa",
        "ed25519",
        "ed448",
        "secp256r1",
        "secp384r1",
        "secp521r1",
    )


@pytest.mark.parametrize("algorithm", ["rsa", "secp256r1"])
def test_signature_hash_for_defaults_to_sha256(algorithm):
    key = cnert.build_private_key(algorithm=algorithm)
    assert isinstance(cnert._signature_hash_for(key), hashes.SHA256)


@pytest.mark.parametrize("algorithm", ["ed25519", "ed448"])
def test_signature_hash_for_edwards_defaults_to_none(algorithm):
    key = cnert.build_private_key(algorithm=algorithm)
    assert cnert._signature_hash_for(key) is None
    assert cnert._signature_hash_for(key, None) is None


@pytest.mark.parametrize("algorithm", ["rsa", "secp384r1"])
def test_signature_hash_for_explicit_hash(algorithm):
    key = cnert.build_private_key(algorithm=algorithm)
    given = hashes.SHA512()
    assert cnert._signature_hash_for(key, given) is given


@pytest.mark.parametrize("algorithm", ["ed25519", "ed448"])
def test_signature_hash_for_edwards_rejects_hash(algorithm):
    key = cnert.build_private_key(algorithm=algorithm)
    with pytest.raises(ValueError, match="take no signature hash"):
        cnert._signature_hash_for(key, hashes.SHA256())


@pytest.mark.parametrize("algorithm", ["rsa", "secp256r1"])
def test_signature_hash_for_requires_hash(algorithm):
    key = cnert.build_private_key(algorithm=algorithm)
    with pytest.raises(ValueError, match="requires a signature hash"):
        cnert._signature_hash_for(key, None)


@pytest.mark.parametrize(
    "hash_algorithm,name",
    [
        (hashes.SHA1(), "sha1"),  # noqa: S303
        (hashes.MD5(), "md5"),  # noqa: S303
    ],
)
def test_signature_hash_for_rejects_unusable_hash(hash_algorithm, name):
    key = cnert.build_private_key()
    with pytest.raises(ValueError, match=f"{name} cannot sign"):
        cnert._signature_hash_for(key, hash_algorithm)


def test_cert_default_signature_hash_is_sha256():
    cert = cnert.CA().issue_cert()
    assert isinstance(cert.certificate.signature_hash_algorithm, hashes.SHA256)


def test_cert_explicit_signature_hash():
    cert = cnert.CA().issue_cert(signature_hash=hashes.SHA384())
    assert isinstance(cert.certificate.signature_hash_algorithm, hashes.SHA384)


def test_cert_signature_hash_sha1_is_refused():
    ca = cnert.CA()
    with pytest.raises(ValueError, match="sha1 cannot sign"):
        ca.issue_cert(signature_hash=hashes.SHA1())  # noqa: S303


def test_CSR_explicit_signature_hash():
    csr = cnert.CSR(signature_hash=hashes.SHA512())
    assert isinstance(csr.CSR.signature_hash_algorithm, hashes.SHA512)


def test_CSR_signature_hash_md5_is_refused():
    with pytest.raises(ValueError, match="md5 cannot sign"):
        cnert.CSR(signature_hash=hashes.MD5())  # noqa: S303


def test_CSR_with_edwards_key():
    key = cnert.build_private_key(algorithm="ed25519")
    csr = cnert.CSR(private_key=key)
    assert csr.CSR.signature_hash_algorithm is None
    assert isinstance(csr.public_key, ed25519.Ed25519PublicKey)


def issuing_cert(algorithm):
    key = cnert.build_private_key(algorithm=algorithm)
    return cnert.Cert(
        subject_attrs=cnert.NameAttrs(ORGANIZATION_NAME="Root CA"),
        issuer_attrs=cnert.NameAttrs(ORGANIZATION_NAME="Root CA"),
        private_key=key,
        path_length=9,
        is_ca=True,
    )


def test_edwards_issuer_signs_without_hash():
    assert issuing_cert("ed25519").certificate.signature_hash_algorithm is (
        None
    )


def test_edwards_issuer_signs_rsa_leaf_without_hash():
    parent = issuing_cert("ed448")
    leaf = cnert.Cert(
        subject_attrs=cnert.NameAttrs(COMMON_NAME="example.com"),
        issuer_attrs=parent.subject_attrs,
        parent=parent,
    )
    assert leaf.certificate.signature_hash_algorithm is None
    assert isinstance(leaf.public_key, rsa.RSAPublicKey)


def test_rsa_issuer_signs_edwards_leaf_with_sha256():
    parent = issuing_cert("rsa")
    leaf = cnert.Cert(
        subject_attrs=cnert.NameAttrs(COMMON_NAME="example.com"),
        issuer_attrs=parent.subject_attrs,
        parent=parent,
        private_key=cnert.build_private_key(algorithm="ed25519"),
    )
    assert isinstance(leaf.certificate.signature_hash_algorithm, hashes.SHA256)
    assert isinstance(leaf.public_key, ed25519.Ed25519PublicKey)


def test_ec_issuer_signs_verifiable_leaf():
    parent = issuing_cert("secp384r1")
    leaf = cnert.Cert(
        subject_attrs=cnert.NameAttrs(COMMON_NAME="example.com"),
        issuer_attrs=parent.subject_attrs,
        parent=parent,
    )
    leaf.certificate.verify_directly_issued_by(parent.certificate)


def edwards_leaf():
    return cnert.Cert(
        subject_attrs=cnert.NameAttrs(COMMON_NAME="example.com"),
        issuer_attrs=cnert.NameAttrs(COMMON_NAME="example.com"),
        private_key=cnert.build_private_key(algorithm="ed25519"),
    )


def test_cert_private_key_pem_PKCS8_for_edwards_key():
    assert edwards_leaf().private_key_pem_PKCS8.startswith(
        b"-----BEGIN PRIVATE KEY-----\n"
    )


def test_cert_private_key_pem_PKCS1_is_rsa_only():
    cert = edwards_leaf()
    with pytest.raises(ValueError, match="PKCS#1 is RSA-only"):
        _ = cert.private_key_pem_PKCS1


def test_CSR_private_key_pem_PKCS1_is_rsa_only():
    csr = cnert.CSR(private_key=cnert.build_private_key(algorithm="ed448"))
    with pytest.raises(ValueError, match="PKCS#1 is RSA-only"):
        _ = csr.private_key_pem_PKCS1


def must_staple():
    return x509.TLSFeature([x509.TLSFeatureType.status_request])


def extension_oids(certificate):
    return [extension.oid for extension in certificate.extensions]


def test_dedupe_extensions_keeps_last_per_oid():
    first = x509.BasicConstraints(ca=False, path_length=None)
    second = x509.BasicConstraints(ca=True, path_length=3)
    pairs = cnert._dedupe_extensions([(first, True), (second, False)])
    assert len(pairs) == 1
    assert pairs[0] == (second, False)


def test_dedupe_extensions_keeps_position_of_first():
    san = x509.SubjectAlternativeName([general_name.DNSName("a.example")])
    first = x509.BasicConstraints(ca=False, path_length=None)
    second = x509.BasicConstraints(ca=True, path_length=3)
    pairs = cnert._dedupe_extensions(
        [(first, True), (san, False), (second, True)]
    )
    assert [extension.oid for extension, _ in pairs] == [
        first.oid,
        san.oid,
    ]


def test_cert_extensions_adds_unmodelled_extension():
    cert = cnert.CA().issue_cert(
        "example.com", extensions=[(must_staple(), False)]
    )
    extension = cert.certificate.extensions.get_extension_for_class(
        x509.TLSFeature
    )
    assert extension.critical is False
    assert list(extension.value) == [x509.TLSFeatureType.status_request]


def test_cert_extensions_keeps_built_in_set():
    ca = cnert.CA()
    plain = ca.issue_cert("example.com")
    extended = ca.issue_cert(
        "example.com", extensions=[(must_staple(), False)]
    )
    assert set(extension_oids(plain.certificate)) < set(
        extension_oids(extended.certificate)
    )


def test_cert_several_extensions():
    policy = x509.CertificatePolicies(
        [x509.PolicyInformation(ObjectIdentifier("1.2.3.4"), None)]
    )
    cert = cnert.CA().issue_cert(
        extensions=[(must_staple(), False), (policy, False)]
    )
    oids = extension_oids(cert.certificate)
    assert must_staple().oid in oids
    assert policy.oid in oids


def test_cert_extension_overrides_key_usage():
    key_usage = x509.KeyUsage(
        content_commitment=False,
        crl_sign=False,
        data_encipherment=True,
        decipher_only=False,
        digital_signature=False,
        encipher_only=False,
        key_agreement=False,
        key_cert_sign=False,
        key_encipherment=False,
    )
    cert = cnert.CA().issue_cert(extensions=[(key_usage, True)])
    found = [
        extension
        for extension in cert.certificate.extensions
        if extension.oid == key_usage.oid
    ]
    assert len(found) == 1
    assert found[0].value.data_encipherment is True
    assert found[0].value.digital_signature is False


def test_CA_extension_overrides_basic_constraints():
    basic_constraints = x509.BasicConstraints(ca=True, path_length=2)
    ca = cnert.CA(extensions=[(basic_constraints, True)])
    found = [
        extension
        for extension in ca.cert.certificate.extensions
        if extension.oid == basic_constraints.oid
    ]
    assert len(found) == 1
    assert found[0].value.path_length == 2


def test_cert_no_extensions_argument_matches_empty_sequence():
    ca = cnert.CA()
    without = ca.issue_cert("example.com")
    empty = ca.issue_cert("example.com", extensions=[])
    assert extension_oids(without.certificate) == extension_oids(
        empty.certificate
    )


def test_CSR_extensions():
    csr = cnert.CSR("example.com", extensions=[(must_staple(), False)])
    extension = csr.CSR.extensions.get_extension_for_class(x509.TLSFeature)
    assert extension.critical is False
    assert list(extension.value) == [x509.TLSFeatureType.status_request]


def test_CSR_without_extensions_is_unchanged():
    csr = cnert.CSR("example.com")
    assert [extension.oid for extension in csr.CSR.extensions] == [
        x509.SubjectAlternativeName.oid
    ]
