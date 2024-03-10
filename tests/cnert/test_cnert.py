# tests/cnert/test_cli.py

from __future__ import annotations  # for Python 3.7-3.9

import datetime
import ipaddress
import re

import cnert
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ObjectIdentifier, extensions, general_name
from cryptography.x509.oid import NameOID


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
    assert exc.type == AttributeError
    assert "This object is frozen!" in str(exc.value)


def test_frozen_attrs_add_attr():
    class Frozen(cnert.Freezer):
        def __init__(self, slot1):
            self.slot1 = slot1
            super().__init__()

    frozen = Frozen(slot1="frozen")
    with pytest.raises(Exception) as exc:
        frozen.slot2 = "not allowed"
    assert exc.type == AttributeError
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
    assert exc.type == AttributeError
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
    assert exc.type == AttributeError
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
    assert exc.type == ValueError
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
    cert = cnert._Cert(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
    assert str(cert) == "Certificate O=Acme,C=AQ,CN=www.example.com"


def test__Cert_default_not_valid_before():
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    before = datetime.datetime.now(datetime.timezone.utc)
    cert = cnert._Cert(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
    assert cert.not_valid_before - before < datetime.timedelta(minutes=1)


def test__Cert_default_not_valid_after():
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        weeks=13
    )
    cert = cnert._Cert(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
    assert cert.not_valid_after - after < datetime.timedelta(minutes=1)


def test__Cert_private_key_size():
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    cert = cnert._Cert(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
    assert cert.private_key.key_size == 2048


def test__Cert_private_key_pem_PKCS1():
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    cert = cnert._Cert(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
    assert cert.private_key_pem_PKCS1.startswith(
        b"-----BEGIN RSA PRIVATE KEY-----\n"
    )
    assert cert.private_key_pem_PKCS1.endswith(
        b"\n-----END RSA PRIVATE KEY-----\n"
    )


def test__Cert_private_key_pem_with_given_private_key(private_key):
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    cert = cnert._Cert(
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
    cert = cnert._Cert(
        subject_attrs=subject_attrs,
        issuer_attrs=issuer_attrs,
        private_key=private_key,
    )
    assert cert.private_key.key_size == 2048


def test__Cert_private_key_pem_PKCS1_with_given_private_key(private_key):
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    cert = cnert._Cert(
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
    cert = cnert._Cert(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
    assert cert.private_key_pem_PKCS8.startswith(
        b"-----BEGIN PRIVATE KEY-----\n"
    )
    assert cert.private_key_pem_PKCS8.endswith(
        b"\n-----END PRIVATE KEY-----\n"
    )


def test__Cert_public_key_pem_PKCS1():
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    cert = cnert._Cert(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
    assert cert.public_key_pem.startswith(b"-----BEGIN PUBLIC KEY-----\n")
    assert cert.public_key_pem.endswith(b"\n-----END PUBLIC KEY-----\n")


def test__Cert_public_key():
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    cert = cnert._Cert(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
    assert isinstance(cert.public_key, rsa.RSAPublicKey)


def test__Cert_serialnumber_is_42():
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    cert = cnert._Cert(
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
    cert1 = cnert._Cert(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
    cert2 = cnert._Cert(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
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


def test__CertBuilder__add_ca_extention():
    cert_builder = cnert._CertBuilder()
    assert len(cert_builder.builder._extensions) == 0
    cert_builder._add_ca_extension()
    assert len(cert_builder.builder._extensions) == 1
    key_usage = cert_builder.builder._extensions[0]
    assert type(key_usage.value) is extensions.KeyUsage
    assert key_usage.oid.dotted_string == "2.5.29.15"
    assert key_usage.value.content_commitment is False
    assert key_usage.value.crl_sign is True
    assert key_usage.value.data_encipherment is False
    assert key_usage.value.digital_signature is True
    assert key_usage.value.key_agreement is False
    assert key_usage.value.key_cert_sign is True
    assert key_usage.value.key_encipherment is True


def test__CertBuilder__add_leaf_cert_extensions_key_usage():
    cert_builder = cnert._CertBuilder()
    assert len(cert_builder.builder._extensions) == 0
    cert_builder._add_leaf_cert_extension()
    assert len(cert_builder.builder._extensions) == 2
    key_usage = cert_builder.builder._extensions[0]
    assert type(key_usage.value) is extensions.KeyUsage
    assert key_usage.oid.dotted_string == "2.5.29.15"
    assert key_usage.value.content_commitment is False
    assert key_usage.value.crl_sign is False
    assert key_usage.value.data_encipherment is False
    assert key_usage.value.digital_signature is True
    assert key_usage.value.key_agreement is False
    assert key_usage.value.key_cert_sign is False
    assert key_usage.value.key_encipherment is True


def test__CertBuilder__add_leaf_cert_extensions_extended_key_usage():
    cert_builder = cnert._CertBuilder()
    assert len(cert_builder.builder._extensions) == 0
    cert_builder._add_leaf_cert_extension()
    assert len(cert_builder.builder._extensions) == 2
    extension = cert_builder.builder._extensions[1]
    assert type(extension.value) is extensions.ExtendedKeyUsage
    assert extension.oid.dotted_string == "2.5.29.37"
    assert list(extension.value) == [
        ObjectIdentifier("1.3.6.1.5.5.7.3.2"),
        ObjectIdentifier("1.3.6.1.5.5.7.3.1"),
        ObjectIdentifier("1.3.6.1.5.5.7.3.3"),
    ]


def test__CertBuilder__add_authority_key_identifier_extension(public_key):
    cert_builder = cnert._CertBuilder()
    assert len(cert_builder.builder._extensions) == 0
    cert_builder._add_authority_key_identifier_extension(public_key)
    assert len(cert_builder.builder._extensions) == 1
    extension = cert_builder.builder._extensions[0]
    assert type(extension.value) is extensions.AuthorityKeyIdentifier
    assert extension.oid.dotted_string == "2.5.29.35"


def test__CertBuilder__add_subject_alt_name_extension():
    cert_builder = cnert._CertBuilder()
    sans = (
        "host1.example.com",
        "host2.example.com",
    )
    cert_builder._add_subject_alt_name_extension(*sans)
    assert len(cert_builder.builder._extensions) == 1
    sub_alt_name = cert_builder.builder._extensions[0]
    assert sub_alt_name.oid.dotted_string == "2.5.29.17"
    assert type(sub_alt_name.value) is extensions.SubjectAlternativeName
    assert list(sub_alt_name.value) == [
        general_name.DNSName(san) for san in sans
    ]


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
        not_valid_before=datetime.datetime.now(datetime.timezone.utc),
        not_valid_after=datetime.datetime.now(datetime.timezone.utc)
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
        not_valid_before=datetime.datetime.now(datetime.timezone.utc),
        not_valid_after=datetime.datetime.now(datetime.timezone.utc)
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
