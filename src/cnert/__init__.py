# cnert/__init__.py

"""
Cnert makes TLS private keys, CSRs, private CAs and certificates.
"""

__version__ = "0.1.5"
__title__ = "Cnert"
__description__ = (
    "Cnert makes TLS private keys, CSRs, private CAs and certificates."
)
__uri__ = "https://github.com/maartenq/cnert"
__author__ = "Maarten"
__email__ = "ikmaarten@gmail.com"
__license__ = "MIT or Apache License, Version 2.0"
__copyright__ = "Copyright (c) 2021  Maarten"


from datetime import datetime, timedelta

# from ipaddress import ip_address, ip_network
from typing import Optional

# import idna
from cryptography import x509
from cryptography.hazmat.backends import default_backend

#
# from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import serialization

# from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.oid import NameOID

# def _idna_encode(_string: str) -> str:
#     for prefix in ["*.", "."]:
#         if _string.startswith(prefix):
#             _string = _string[len(prefix) :]
#             _bytes = prefix.encode("ascii") + \
#                    idna.encode(_string, uts46=True)
#             return _bytes.decode("ascii")
#     return idna.encode(_string, uts46=True).decode("ascii")


# def _identity_string_to_x509(identity: str) -> x509.GeneralName:
#     try:
#         return x509.IPAddress(ip_address(identity))
#     except ValueError:
#         try:
#             return x509.IPAddress(ip_network(identity))
#         except ValueError:
#             if "@" in identity:
#                 return x509.RFC822Name(identity)
#             return x509.DNSName(_idna_encode(identity))


# def _key_usage(
#     content_commitment: bool = False,
#     crl_sign: bool = False,
#     data_encipherment: bool = False,
#     decipher_only: bool = False,
#     digital_signature: bool = True,
#     encipher_only: bool = False,
#     key_agreement: bool = False,
#     key_cert_sign: bool = False,
#     key_encipherment: bool = True,
# ) -> x509.KeyUsage:
#     return x509.KeyUsage(
#         content_commitment=content_commitment,
#         crl_sign=crl_sign,
#         data_encipherment=data_encipherment,
#         decipher_only=decipher_only,
#         digital_signature=digital_signature,
#         encipher_only=encipher_only,
#         key_agreement=key_agreement,
#         key_cert_sign=key_cert_sign,
#         key_encipherment=key_encipherment,
#     )


# def _x509_name(**name_attrs: str) -> x509.Name:
#     """
#     Takes optional Name Attribute key/values as keyword arguments.
#     """

#     _DEFAULT_NAME_ATTRS: Dict[str, str] = {
#         "BUSINESS_CATEGORY:str = "Business Category",
#         "COMMON_NAME:str = "Common Name",
#         "COUNTRY_NAME:str = "US",
#         "DN_QUALIFIER:str = "DN qualifier",
#         "DOMAIN_COMPONENT:str = "Domain Component",
#         "EMAIL_ADDRESS:str = "info@example.com",
#         "GENERATION_QUALIFIER:str = "Generation Qualifier",
#         "GIVEN_NAME:str = "Given Name",
#         "INN:str = "INN",
#         "JURISDICTION_COUNTRY_NAME:str = "US",
#         "JURISDICTION_LOCALITY_NAME:str = "Jurisdiction Locality Name",
#         "JURISDICTION_STATE_OR_PROVINCE_NAME": (
#             "Jurisdiction State or Province Name"
#         ),
#         "LOCALITY_NAME:str = "Locality Name",
#         "OGRN:str = "OGRN",
#         "ORGANIZATIONAL_UNIT_NAME:str = "Organizational unit_name",
#         "ORGANIZATION_NAME:str = "Organization Name",
#         "POSTAL_ADDRESS:str = "Postal Address",
#         "POSTAL_CODE:str = "Postal Code",
#         "PSEUDONYM:str = "Pseudonym",
#         "SERIAL_NUMBER:str = "42",
#         "SNILS:str = "SNILS",
#         "STATE_OR_PROVINCE_NAME:str = "State or Province Name",
#         "STREET_ADDRESS:str = "Street Address",
#         "SURNAME:str = "Surname",
#         "TITLE:str = "Title",
#         "UNSTRUCTURED_NAME:str = "unstructuredName",
#         "USER_ID:str = "User ID",
#         "X500_UNIQUE_IDENTIFIER:str = "X500 Unique Identifier",
#     }
#     name_attrs = {key.upper(): value for key, value in name_attrs.items()}
#     if not name_attrs:
#         name_attrs = _DEFAULT_NAME_ATTRS.copy()
#     return x509.Name(
#         [
#             x509.NameAttribute(getattr(NameOID, key), value)
#             for (key, value) in name_attrs.items()
#         ]
#     )


# def _add_ca_extension(
#     cert_builder: x509.CertificateBuilder,
# ) -> x509.CertificateBuilder:
#     return cert_builder.add_extension(
#         _key_usage(
#             digital_signature=True,
#             key_cert_sign=True,
#             crl_sign=True,
#         ),
#         critical=True,
#     )


# def _add_leaf_cert_extensions(
#     cert_builder: x509.CertificateBuilder,
# ) -> x509.CertificateBuilder:
#     return cert_builder.add_extension(
#         _key_usage(),
#         critical=True,
#     ).add_extension(
#         x509.ExtendedKeyUsage(
#             [
#                 ExtendedKeyUsageOID.CLIENT_AUTH,
#                 ExtendedKeyUsageOID.SERVER_AUTH,
#                 ExtendedKeyUsageOID.CODE_SIGNING,
#             ]
#         ),
#         critical=True,
#     )


# def _add_subject_alt_name_extension(
#     cert_builder: x509.CertificateBuilder,
#     *identities: str,
# ) -> x509.CertificateBuilder:
#     return cert_builder.add_extension(
#         x509.SubjectAlternativeName(
#             [_identity_string_to_x509(ident) for ident in identities]
#         ),
#         critical=True,
#     )


# def _cert_builder(
#     *identities: str,
#     subject: x509.Name,
#     issuer: x509.Name,
#     public_key: rsa.RSAPublicKey,
#     not_valid_before: datetime,
#     not_valid_after: datetime,
#     serial_number: int = 0,
#     ca: bool = False,
#     path_length: Optional[int] = None,
# ) -> x509.CertificateBuilder:
#     serial_number = serial_number or x509.random_serial_number()
#     cert_builder = (
#         x509.CertificateBuilder()
#         .subject_name(subject)
#         .issuer_name(issuer)
#         .public_key(public_key)
#         .serial_number(serial_number)
#         .not_valid_before(not_valid_before)
#         .not_valid_after(not_valid_after)
#         .add_extension(
#             x509.SubjectKeyIdentifier.from_public_key(public_key),
#             critical=False,
#         )
#         .add_extension(
#             x509.BasicConstraints(ca=ca, path_length=path_length),
#             critical=True,
#         )
#     )
#     if ca:
#         cert_builder = _add_ca_extension(cert_builder)
#     else:
#         cert_builder = _add_leaf_cert_extensions(cert_builder)
#     if identities:
#         cert_builder = _add_subject_alt_name_extension(
#             cert_builder, *identities
#         )
#     return cert_builder


# class _Cert:
#     public_key: rsa.RSAPublicKey
#     private_key: rsa.RSAPrivateKey
#
#     def __init__(
#         self,
#         subject_attrs: Dict[str, str],
#         issuer_attrs: Dict[str, str],
#         path_length: int,
#         not_valid_before: datetime,
#         not_valid_after: datetime,
#         parent: Optional["_Cert"] = None,
#     ):
#         self.subject_attrs = subject_attrs
#         self.issuer_attrs = issuer_attrs
#         self.path_length = path_length
#         self.parent = parent
#         self.not_valid_before = not_valid_before
#         self.not_valid_after = not_valid_after
#         self.private_key = _private_key()
#         self.public_key = self.private_key.public_key()
#         self.private_key_pem = _private_key_pem(self.private_key)


class Freezer:
    """
    Freeze any class such that instantiated objects become immutable.
    """

    __slots__: list[str] = []
    _frozen: bool = False

    def __init__(self):
        for attr_name in dir(self):
            self.__slots__.append(attr_name)
        self._frozen = True

    def __delattr__(self, *args, **kwargs):
        if self._frozen:
            raise AttributeError("This object is frozen!")
        object.__delattr__(self, *args, **kwargs)

    def __setattr__(self, *args, **kwargs):
        if self._frozen:
            raise AttributeError("This object is frozen!")
        object.__setattr__(self, *args, **kwargs)


class NameAttrs(Freezer):
    """
    An object for storing (and freezing) Name Attributes for Subject Name
    Attributes and Issuer Name Attributes.

    Accepts any valid x509.NameAttribute as key arguments with arbitrary string
    values.

    Has methods for returning initialized attributes in a dict and for
    returning a `cryptography.x509.Name`

    There is alse a method for showing the allowed attributes.

    Examples:
        >>> subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
        >>> subject_attrs.COMMON_NAME
        'example.com'
        >>> subject_attrs.dict_
        {'COMMON_NAME': 'example.com'}
        >>> subject_attrs.x509_name
        <Name(CN=example.com)>
    """

    BUSINESS_CATEGORY: str
    COMMON_NAME: str
    COUNTRY_NAME: str
    DN_QUALIFIER: str
    DOMAIN_COMPONENT: str
    EMAIL_ADDRESS: str
    GENERATION_QUALIFIER: str
    GIVEN_NAME: str
    INN: str
    JURISDICTION_COUNTRY_NAME: str
    JURISDICTION_LOCALITY_NAME: str
    JURISDICTION_STATE_OR_PROVINCE_NAME: str
    LOCALITY_NAME: str
    OGRN: str
    ORGANIZATIONAL_UNIT_NAME: str
    ORGANIZATION_NAME: str
    POSTAL_ADDRESS: str
    POSTAL_CODE: str
    PSEUDONYM: str
    SERIAL_NUMBER: str
    SNILS: str
    STATE_OR_PROVINCE_NAME: str
    STREET_ADDRESS: str
    SURNAME: str
    TITLE: str
    UNSTRUCTURED_NAME: str
    USER_ID: str
    X500_UNIQUE_IDENTIFIER: str

    def __init__(self, **kwargs) -> None:
        self._name_oids: list[x509.NameAttribute] = []
        self.dict_: dict[str, str] = {}
        keys = list(kwargs.keys())
        keys.sort()
        for key in keys:
            self._name_oids.append(
                x509.NameAttribute(getattr(NameOID, key), kwargs[key])
            )
            setattr(self, key, kwargs[key])
            self.dict_[key] = kwargs[key]
        super().__init__()

    def x509_name(self) -> x509.Name:
        """
        Examples:
            >>> subject_attrs = cnert.NameAttrs(COMMON_NAME="example.com")
            >>> subject_attrs.x509_name()
            <Name(CN=example.com)>

        Returns:
            A `cryptography.x509.Name`
        """
        return x509.Name(self._name_oids)

    def allowed_keys(self) -> list[str]:
        """
        Returns a list of allowed key arguments.

        Examples:
            >>> cnert.NameAttrs().allowed_keys()
            ['BUSINESS_CATEGORY',
             'COMMON_NAME',
             'COUNTRY_NAME',
             'DN_QUALIFIER',
             'DOMAIN_COMPONENT',
             'EMAIL_ADDRESS',
             'GENERATION_QUALIFIER',
             'GIVEN_NAME',
             'INN',
             'JURISDICTION_COUNTRY_NAME',
             'JURISDICTION_LOCALITY_NAME',
             'JURISDICTION_STATE_OR_PROVINCE_NAME',
             'LOCALITY_NAME',
             'OGRN',
             'ORGANIZATIONAL_UNIT_NAME',
             'ORGANIZATION_NAME',
             'POSTAL_ADDRESS',
             'POSTAL_CODE',
             'PSEUDONYM',
             'SERIAL_NUMBER',
             'SNILS',
             'STATE_OR_PROVINCE_NAME',
             'STREET_ADDRESS',
             'SURNAME',
             'TITLE',
             'UNSTRUCTURED_NAME',
             'USER_ID',
             'X500_UNIQUE_IDENTIFIER']

        Returns:
            A list of valid key attributes.
        """
        return sorted(self.__class__.__dict__["__annotations__"].keys())

    def __eq__(self, other) -> bool:
        return self.dict_ == other.dict_

    def __str__(self) -> str:
        return self.x509_name().rfc4514_string()

    def __repr__(self) -> str:
        args = ", ".join(f'{x[0]}="{x[1]}"' for x in self.dict_.items())
        return f"NameAttrs({args})"


class _Cert:
    """
    A _Cert object.

    This object is returned by [`cnert.CA().issue_cert()`][cnert.CA.issue_cert]

    Examples:

        >>> ca = CA()
        >>> cert = ca.issue_cert()
        >>> cert.subject_attrs
        NameAttrs(COMMON_NAME="example.com")
        >>> cert.issuer_attrs
        NameAttrs(ORGANIZATION_NAME="Root CA")
        >>> cert.not_valid_before
        datetime.datetime(2023, 3, 24, 23, 56, 55, 901545)
        >>> cert.not_valid_after
        datetime.datetime(2023, 6, 23, 23, 56, 55, 901545)

    """

    def __init__(
        self,
        subject_attrs: NameAttrs,
        issuer_attrs: NameAttrs,
        path_length: int = 0,
        not_valid_before: Optional[datetime] = None,
        not_valid_after: Optional[datetime] = None,
    ) -> None:
        if not_valid_before is None:
            not_valid_before = datetime.utcnow()

        if not_valid_after is None:
            not_valid_after = not_valid_before + timedelta(weeks=13)

        self.subject_attrs = subject_attrs
        self.issuer_attrs = issuer_attrs
        self.path_length = path_length
        self.not_valid_before = not_valid_before
        self.not_valid_after = not_valid_after
        (
            self.private_key,
            self.public_key,
            self.private_key_pem,
        ) = self._gen_private_key()

    @staticmethod
    def _gen_private_key(
        key_size: int = 2048, public_exponent: int = 65537
    ) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey, bytes]:
        key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size,
            backend=default_backend(),
        )
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return (key, key.public_key(), pem)

    def __str__(self) -> str:
        return f"Certificate {self.subject_attrs}"


class CA:
    """
    A CA object.

    Examples:
        >>> ca = cnert.CA()
        >>> ca.is_root_ca
        True
        >>> ca.is_intermediate_ca
        False
        >>> ca.parent is None
        True

    Parameters:
        subject_attrs: Subject Name Attributes
        not_valid_before: CA not valid before date
        not_valid_after: CA not valid after date

    """

    def __init__(
        self,
        subject_attrs: Optional[NameAttrs] = None,
        issuer_attrs: Optional[NameAttrs] = None,
        path_length: int = 9,
        not_valid_before: Optional[datetime] = None,
        not_valid_after: Optional[datetime] = None,
        parent: Optional["CA"] = None,
        intermediate_num: int = 0,
    ) -> None:
        self.intermediate_num = intermediate_num
        self.parent = parent

        # A CA is self signed so it is its own issuer.
        if self.is_root_ca and subject_attrs != issuer_attrs:
            raise ValueError(
                "Can't create CA: issuer attributes must be same "
                "as subject attributes"
            )

        if subject_attrs is None:
            subject_attrs = NameAttrs(ORGANIZATION_NAME="Root CA")

        if issuer_attrs is None:
            issuer_attrs = subject_attrs

        self.cert = _Cert(
            subject_attrs=subject_attrs,
            issuer_attrs=issuer_attrs,
            path_length=path_length,
            not_valid_before=not_valid_before,
            not_valid_after=not_valid_after,
        )

    def __str__(self) -> str:
        return f"CA {self.cert.subject_attrs}"

    @property
    def is_root_ca(self) -> bool:
        """
        Examples:
            >>> ca = CA()
            >>> ca.is_root_ca
            True
            >>> intermediate = ca.issue_intermediate()
            >>> intermediate.is_root_ca
            False

        Returns:
            Whether CA is a root CA or not.
        """
        return self.intermediate_num < 1

    @property
    def is_intermediate_ca(self) -> bool:
        """
        Returns:
            Whether CA is a intermediate CA or not.
        """
        return self.intermediate_num > 0

    def issue_intermediate(
        self,
        subject_attrs: Optional[NameAttrs] = None,
        not_valid_before: Optional[datetime] = None,
        not_valid_after: Optional[datetime] = None,
    ) -> "CA":
        if self.cert.path_length == 0:
            raise ValueError("Can't create intermediate CA: path length is 0")
        intermediate_num = self.intermediate_num + 1
        return CA(
            subject_attrs=subject_attrs
            or NameAttrs(
                ORGANIZATION_NAME=f"CA Intermediate {intermediate_num}"
            ),
            issuer_attrs=self.cert.subject_attrs,
            path_length=self.cert.path_length - 1,
            not_valid_before=not_valid_before or self.cert.not_valid_before,
            not_valid_after=not_valid_after or self.cert.not_valid_after,
            parent=self,
            intermediate_num=intermediate_num,
        )

    def issue_cert(
        self,
        subject_attrs: Optional[NameAttrs] = None,
        not_valid_before: Optional[datetime] = None,
        not_valid_after: Optional[datetime] = None,
    ) -> "_Cert":
        """
        Issues a certificate

        Examples:
            >>> ca = CA()
            >>> ca.issue_cert()
            <cnert.Cert at 0x107f87f50>

        Parameters:
            subject_attrs: Subject Name Attributes
            not_valid_before: Certificate not valid before date
            not_valid_after: Certificate not valid after date

        Returns:
            A _Cert object.

        """

        if subject_attrs is None:
            subject_attrs = NameAttrs(COMMON_NAME="example.com")
        return _Cert(
            subject_attrs=subject_attrs,
            issuer_attrs=self.cert.subject_attrs,
            not_valid_before=not_valid_before,
            not_valid_after=not_valid_after,
        )

    # def create_intermediate(
    #     self, subject_attrs: Optional[Dict[str, str]] = None
    # ) -> "CA":
    #     if subject_attrs is None:
    #         subject_attrs = {"ORGANIZATION_NAME:str = "Intermediate CA"}
    #     if self.cert.path_length == 0:
    #         raise ValueError(
    #            "Can't create intermediate CA: path length is 0"
    #           )
    #     return CA(
    #         subject_attrs=subject_attrs,
    #         parent=self.cert,
    #         path_length=self.cert.path_length - 1,
    #     )


#
#     def __init__(
#         self,
#         subject_attrs: Optional[Dict[str, str]] = None,
#         parent: Optional[_Cert] = None,
#         not_valid_before: Optional[datetime] = None,
#         not_valid_after: Optional[datetime] = None,
#         path_length: int = 9,
#     ) -> None:
#         if subject_attrs is None:
#             subject_attrs = {"ORGANIZATION_NAME:str = "Root CA"}
#         now = datetime.utcnow()
#         issuer_attrs = parent.subject_attrs if parent else subject_attrs
#
#         self.cert = _Cert(
#             subject_attrs=subject_attrs,
#             issuer_attrs=issuer_attrs,
#             path_length=path_length,
#             not_valid_before=not_valid_before or now,
#             not_valid_after=not_valid_after or now + timedelta(weeks=13),
#             parent=parent,
#         )
#
#     def issues_cert(self):
#         pass
#
#     def create_intermediate(
#         self, subject_attrs: Optional[Dict[str, str]] = None
#     ) -> "CA":
#         if subject_attrs is None:
#             subject_attrs = {"ORGANIZATION_NAME:str = "Intermediate CA"}
#         if self.cert.path_length == 0:
#             raise ValueError(
#                "Can't create intermediate CA: path length is 0"
#               )
#         return CA(
#             subject_attrs=subject_attrs,
#             parent=self.cert,
#             path_length=self.cert.path_length - 1,
#         )
#
#     def create_cert(
#         self,
#         *identities: str,
#         subject_attrs: Dict[str, str],
#         not_valid_before: datetime,
#         not_valid_after: datetime,
#     ) -> None:
#         pass

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
