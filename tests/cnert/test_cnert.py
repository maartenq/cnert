# tests/cnert/test_cli.py

# import ipaddress
# from typing import Dict


from datetime import datetime, timedelta

import cnert
import pytest
from cryptography import x509

# from cnert.cert import (
#     _add_ca_extension,
#     _add_leaf_cert_extensions,
#     _add_subject_alt_name_extension,
#     _identity_string_to_x509,
#     _idna_encode,
#     _key_usage,
#     _private_key,
#     _private_key_pem,
#     _x509_name,
# )
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.x509 import ObjectIdentifier, extensions, general_name
# from cryptography.x509.extensions import (
#     ExtendedKeyUsage,
#     KeyUsage,
#     SubjectAlternativeName,
# )
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
    assert repr(name_attrs) == (
        "NameAttrs("
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

    assert repr(name_attrs) == (
        'NameAttrs(COMMON_NAME="example.com", COUNTRY_NAME="AT", '
        'EMAIL_ADDRESS="info@example.com", LOCALITY_NAME="Salzburg", '
        'STREET_ADDRESS="Getreidegasse 9")'
    )


def test_name_attrs__str__with_default_name_attrs_names(default_name_attrs):
    name_attrs = cnert.NameAttrs(**default_name_attrs)
    assert str(name_attrs) == (
        "2.5.4.45=X500 unique identifier,"
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

    assert str(name_attrs) == (
        "STREET=Getreidegasse 9,"
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


def test_ca__str__():
    ca = cnert.CA()
    assert str(ca) == "CA O=Root CA"


def test_ca_is_root_ca_not_intemediate():
    ca = cnert.CA()
    assert ca.is_root_ca
    assert not ca.is_intermediate_ca


def test_ca_parent_is_none():
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


def test_ca_default_name_attr_common_name():
    ca = cnert.CA()
    assert ca.cert.subject_attrs.ORGANIZATION_NAME == "Root CA"


def test_ca_subject_attrs_is_issue_attrs():
    ca = cnert.CA()
    assert ca.cert.subject_attrs == ca.cert.issuer_attrs


def test_ca_subject_attrs_is_not_issue_attrs():
    subject_attrs = cnert.NameAttrs(ORGANIZATION_NAME="A")
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="B")
    with pytest.raises(Exception) as exc:
        cnert.CA(subject_attrs=subject_attrs, issuer_attrs=issuer_attrs)
    assert exc.type == ValueError
    assert (
        "Can't create CA: issuer attributes must be same as subject attributes"
        in str(exc.value)
    )


def test_ca_issue_intermediate_first():
    ca = cnert.CA()
    intermediate_1 = ca.issue_intermediate()
    assert (
        intermediate_1.cert.subject_attrs.ORGANIZATION_NAME
        == "CA Intermediate 1"
    )
    assert intermediate_1.cert.path_length == 8


def test_ca_issue_intermediate_second():
    ca = cnert.CA()
    intermediate_1 = ca.issue_intermediate()
    intermediate_2 = intermediate_1.issue_intermediate()
    assert (
        intermediate_2.cert.subject_attrs.ORGANIZATION_NAME
        == "CA Intermediate 2"
    )
    assert intermediate_2.cert.path_length == 7


def test_ca_issue_intermediate_max_path_lenght():
    ca = cnert.CA(path_length=2)
    intermediate_1 = ca.issue_intermediate()
    intermediate_2 = intermediate_1.issue_intermediate()
    with pytest.raises(Exception) as exc:
        intermediate_2.issue_intermediate()
    assert exc.type == ValueError
    assert "Can't create intermediate CA: path length is 0" in str(exc.value)


def test_ca_issue_cert_default_common_name_is_example_com():
    ca = cnert.CA()
    cert = ca.issue_cert()
    assert cert.subject_attrs.COMMON_NAME == "example.com"


def test_ca_issue_cert_default_common_name_is_www_example_com():
    ca = cnert.CA()
    subject_attrs = cnert.NameAttrs(COMMON_NAME="www.example.com")
    cert = ca.issue_cert(subject_attrs=subject_attrs)
    assert cert.subject_attrs.COMMON_NAME == "www.example.com"


def test_cert__str__():
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(
        COMMON_NAME="www.example.com",
        COUNTRY_NAME="AQ",
        ORGANIZATION_NAME="Acme",
    )
    cert = cnert._Cert(subject_attrs, issuer_attrs)
    assert str(cert) == "Certificate O=Acme,C=AQ,CN=www.example.com"


def test_cert_default_not_valid_before():
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    before = datetime.now()
    cert = cnert._Cert(subject_attrs, issuer_attrs)
    assert cert.not_valid_before - before < timedelta(minutes=1)


def test_cert_default_not_valid_after():
    issuer_attrs = cnert.NameAttrs(ORGANIZATION_NAME="CA")
    subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
    after = datetime.now() + timedelta(weeks=13)
    cert = cnert._Cert(subject_attrs, issuer_attrs)
    assert cert.not_valid_after - after < timedelta(minutes=1)


# def test__idna_encode():
#     assert _idna_encode("*.example.com") == "*.example.com"
#     assert _idna_encode("*.éxample.com") == "*.xn--xample-9ua.com"
#     assert _idna_encode("Example.com") == "example.com"
#
#
# def test__identity_string_to_x509_IPAddress():
#     x509_IP = _identity_string_to_x509("198.51.100.1")
#     assert type(x509_IP) is general_name.IPAddress
#     assert x509_IP.value == ipaddress.IPv4Address("198.51.100.1")
#
#
# def test__identity_string_to_x509_NetWork():
#     x509_network = _identity_string_to_x509("198.51.100.0/24")
#     assert type(x509_network) is general_name.IPAddress
#     assert x509_network.value == ipaddress.IPv4Network("198.51.100.0/24")
#
#
# def test__identity_string_to_x509_RFC822Name():
#     x509_email_addr = _identity_string_to_x509("harry@example.com")
#     assert type(x509_email_addr) is general_name.RFC822Name
#     assert x509_email_addr.value == "harry@example.com"
#
#
# def test__identity_string_to_x509_DNSName():
#     x509_dns_name = _identity_string_to_x509("host.example.com")
#     assert type(x509_dns_name) is general_name.DNSName
#     assert x509_dns_name.value == "host.example.com"
#
#
# def test__private_key():
#     private_key = _private_key()
#     assert private_key.key_size == 2048
#
#
# def test__private_key_pem():
#     pem = _private_key_pem(
#         rsa.generate_private_key(
#             public_exponent=65537,
#             key_size=2048,
#             backend=default_backend(),
#         )
#     )
#     assert b"-----BEGIN RSA PRIVATE KEY-----" in pem
#     assert b"-----END RSA PRIVATE KEY-----" in pem
#
#
# def test__key_usage_defaults():
#     key_usage = _key_usage()
#     assert type(key_usage) is extensions.KeyUsage
#     assert key_usage.content_commitment is False
#     assert key_usage.crl_sign is False
#     assert key_usage.data_encipherment is False
#     assert key_usage.digital_signature is True
#     # assert key_usage.decipher_only is False
#     # assert key_usage.encipher_only is False
#     assert key_usage.key_agreement is False
#     assert key_usage.key_cert_sign is False
#     assert key_usage.key_encipherment is True
#
#
# def test__key_usage_ca():
#     key_usage = _key_usage(
#         digital_signature=True,
#         key_cert_sign=True,
#         crl_sign=True,
#     )
#     assert type(key_usage) is extensions.KeyUsage
#     assert key_usage.content_commitment is False
#     assert key_usage.crl_sign is True
#     assert key_usage.data_encipherment is False
#     assert key_usage.digital_signature is True
#     # assert key_usage.decipher_only is False
#     # assert key_usage.encipher_only is False
#     assert key_usage.key_agreement is False
#     assert key_usage.key_cert_sign is True
#     assert key_usage.key_encipherment is True
#
#
# def test_X509Name_default(default_name_attrs):
#     assert _x509_name() == x509.Name(
#         [
#             x509.NameAttribute(getattr(NameOID, key), value)
#             for (key, value) in default_name_attrs.items()
#         ]
#     )
#
#
# def test_X509Name_with_key_arguments():
#     NAME_ATTRS: Dict[str, str] = {
#         "COMMON_NAME": "Jansen",
#         "COUNTRY_NAME": "NL",
#         "EMAIL_ADDRESS": "harry@example.com",
#         "GIVEN_NAME": "Harry de Groot",
#     }
#     assert _x509_name(**NAME_ATTRS) == x509.Name(
#         [
#             x509.NameAttribute(getattr(NameOID, key), value)
#             for (key, value) in NAME_ATTRS.items()
#         ]
#     )
#
#
# def test_X509Name_with_lower_key_arguments():
#     NAME_ATTRS: Dict[str, str] = {
#         "common_name": "Jansen",
#         "country_name": "NL",
#         "email_address": "harry@example.com",
#         "given_name": "Harry de Groot",
#     }
#     assert _x509_name(**NAME_ATTRS) == x509.Name(
#         [
#             x509.NameAttribute(getattr(NameOID, key.upper()), value)
#             for (key, value) in NAME_ATTRS.items()
#         ]
#     )
#
#
# def test_X509Name_raises_exception():
#     with pytest.raises(AttributeError):
#         _x509_name(NON_EXISTING_NAME_ATTR="should not exist")
#
#
# def test__add_ca_extention():
#     builder = _add_ca_extension(x509.CertificateBuilder())
#     key_usage = builder._extensions[0].value
#     assert type(key_usage) is extensions.KeyUsage
#     assert key_usage.content_commitment is False
#     assert key_usage.crl_sign is True
#     assert key_usage.data_encipherment is False
#     assert key_usage.digital_signature is True
#     # assert key_usage.decipher_only is False
#     # assert key_usage.encipher_only is False
#     assert key_usage.key_agreement is False
#     assert key_usage.key_cert_sign is True
#     assert key_usage.key_encipherment is True
#
#
# def test__add_leaf_cert_extensions_key_usage():
#     builder = _add_leaf_cert_extensions(x509.CertificateBuilder())
#     key_usage = builder._extensions[0].value
#     assert type(key_usage) is KeyUsage
#     assert key_usage.content_commitment is False
#     assert key_usage.crl_sign is False
#     assert key_usage.data_encipherment is False
#     assert key_usage.digital_signature is True
#     # assert key_usage.decipher_only is False
#     # assert key_usage.encipher_only is False
#     assert key_usage.key_agreement is False
#     assert key_usage.key_cert_sign is False
#     assert key_usage.key_encipherment is True
#
#
# def test__add_leaf_cert_extensions_extended_key_usage():
#     builder = _add_leaf_cert_extensions(x509.CertificateBuilder())
#     ext_key_usage = builder._extensions[1].value
#     assert type(ext_key_usage) is ExtendedKeyUsage
#     assert list(ext_key_usage) == [
#         ObjectIdentifier("1.3.6.1.5.5.7.3.2"),
#         ObjectIdentifier("1.3.6.1.5.5.7.3.1"),
#         ObjectIdentifier("1.3.6.1.5.5.7.3.3"),
#     ]
#
#
# def test__add_subject_alt_name_extension():
#     hostnames = [
#         "host1.example.com",
#         "host2.example.com",
#     ]
#     builder = _add_subject_alt_name_extension(
#         x509.CertificateBuilder(),
#         *hostnames,
#     )
#     ext_alt_name = builder._extensions[0].value
#     assert type(ext_alt_name) is SubjectAlternativeName
#     assert list(ext_alt_name) == [
#         general_name.DNSName(hostname) for hostname in hostnames
#     ]
