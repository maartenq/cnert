# cnert/cert.py

"""cert.py package for cnert."""

from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network
from typing import Dict, Optional

import idna
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _idna_encode(string: str) -> str:
    for prefix in ["*.", "."]:
        if string.startswith(prefix):
            string = string[len(prefix) :]  # noqa E203
            bytes = prefix.encode("ascii") + idna.encode(string, uts46=True)
            return bytes.decode("ascii")
    return idna.encode(string, uts46=True).decode("ascii")


def _identity_string_to_x509(identity: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ip_address(identity))
    except ValueError:
        try:
            return x509.IPAddress(ip_network(identity))
        except ValueError:
            if "@" in identity:
                return x509.RFC822Name(identity)
            return x509.DNSName(_idna_encode(identity))


def _private_key(
    key_size: int = 2048,
    public_exponent: int = 65537,
) -> rsa.RSAPrivateKey:
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
        backend=default_backend(),
    )
    return private_key


def _private_key_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem


def _key_usage(
    content_commitment: bool = False,
    crl_sign: bool = False,
    data_encipherment: bool = False,
    decipher_only: bool = False,
    digital_signature: bool = True,
    encipher_only: bool = False,
    key_agreement: bool = False,
    key_cert_sign: bool = False,
    key_encipherment: bool = True,
) -> x509.KeyUsage:
    return x509.KeyUsage(
        content_commitment=content_commitment,
        crl_sign=crl_sign,
        data_encipherment=data_encipherment,
        decipher_only=decipher_only,
        digital_signature=digital_signature,
        encipher_only=encipher_only,
        key_agreement=key_agreement,
        key_cert_sign=key_cert_sign,
        key_encipherment=key_encipherment,
    )


def _x509_name(**name_attrs: str) -> x509.Name:
    """
    Takes optional Name Attribute key/values as keyword arguments.
    """

    _DEFAULT_NAME_ATTRS: Dict[str, str] = dict(
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
    name_attrs = {key.upper(): value for key, value in name_attrs.items()}
    if not name_attrs:
        name_attrs = _DEFAULT_NAME_ATTRS.copy()
    return x509.Name(
        [
            x509.NameAttribute(getattr(NameOID, key), value)
            for (key, value) in name_attrs.items()
        ]
    )


def _add_ca_extension(
    cert_builder: x509.CertificateBuilder,
) -> x509.CertificateBuilder:
    return cert_builder.add_extension(
        _key_usage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
        ),
        critical=True,
    )


def _add_leaf_cert_extensions(
    cert_builder: x509.CertificateBuilder,
) -> x509.CertificateBuilder:
    return cert_builder.add_extension(
        _key_usage(),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage(
            [
                ExtendedKeyUsageOID.CLIENT_AUTH,
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CODE_SIGNING,
            ]
        ),
        critical=True,
    )


def _add_subject_alt_name_extension(
    cert_builder: x509.CertificateBuilder,
    *identities: str,
) -> x509.CertificateBuilder:
    return cert_builder.add_extension(
        x509.SubjectAlternativeName(
            [_identity_string_to_x509(ident) for ident in identities]
        ),
        critical=True,
    )


def _cert_builder(
    *identities: str,
    subject: x509.Name,
    issuer: x509.Name,
    public_key: rsa.RSAPublicKey,
    not_valid_before: datetime,
    not_valid_after: datetime,
    serial_number: int = 0,
    ca: bool = False,
    path_length: Optional[int] = None,
) -> x509.CertificateBuilder:
    serial_number = serial_number or x509.random_serial_number()
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial_number)
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=ca, path_length=path_length),
            critical=True,
        )
    )
    if ca:
        cert_builder = _add_ca_extension(cert_builder)
    else:
        cert_builder = _add_leaf_cert_extensions(cert_builder)
    if identities:
        cert_builder = _add_subject_alt_name_extension(
            cert_builder, *identities
        )
    return cert_builder


class _Cert:
    public_key: rsa.RSAPublicKey
    private_key: rsa.RSAPrivateKey

    def __init__(
        self,
        subject_attrs: Dict[str, str],
        issuer_attrs: Dict[str, str],
        path_length: int,
        not_valid_before: datetime,
        not_valid_after: datetime,
        parent: Optional["_Cert"] = None,
    ):
        self.subject_attrs = subject_attrs
        self.issuer_attrs = issuer_attrs
        self.path_length = path_length
        self.parent = parent
        self.not_valid_before = not_valid_before
        self.not_valid_after = not_valid_after
        self.private_key = _private_key()
        self.public_key = self.private_key.public_key()
        self.private_key_pem = _private_key_pem(self.private_key)


class CA:
    """A Certificate Authority

    A root CA or an intermediate CA.

    """

    def __init__(
        self,
        subject_attrs: Dict[str, str] = dict(ORGANIZATION_NAME="Root CA"),
        parent: Optional[_Cert] = None,
        not_valid_before: Optional[datetime] = None,
        not_valid_after: Optional[datetime] = None,
        path_length: int = 9,
    ) -> None:
        now = datetime.utcnow()
        if parent:
            issuer_attrs = parent.subject_attrs
        else:
            issuer_attrs = subject_attrs

        self.cert = _Cert(
            subject_attrs=subject_attrs,
            issuer_attrs=issuer_attrs,
            path_length=path_length,
            not_valid_before=not_valid_before or now,
            not_valid_after=not_valid_after or now + timedelta(weeks=13),
            parent=parent,
        )

    def issues_cert(self):
        pass

    def create_intermediate(
        self,
        subject_attrs: Dict[str, str] = dict(
            ORGANIZATION_NAME="Intermediate CA"
        ),
    ) -> "CA":
        if self.cert.path_length == 0:
            raise ValueError("Can't create intermediate CA: path length is 0")
        return CA(
            subject_attrs=subject_attrs,
            parent=self.cert,
            path_length=self.cert.path_length - 1,
        )

    def create_cert(
        self,
        *identities: str,
        subject_attrs: Dict[str, str],
        not_valid_before: datetime,
        not_valid_after: datetime,
    ) -> None:
        pass

        # certificate: x509.Certificate = _cert_builder(
        #     subject=_x509_name(**subject_attrs),
        #     issuer=_x509_name(**self.cert.issuer),
        #     public_key=self.cert.public_key,
        #     not_valid_before=not_valid_before,
        #     not_valid_after=not_valid_after,
        # ).sign(
        #     private_key=self.cert.private_key,
        #     algorithm=hashes.SHA256(),
        #     backend=default_backend(),
        # )
