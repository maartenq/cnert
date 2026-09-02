# cnert/__init__.py

from __future__ import annotations  # lazy annotations; drop when floor >= 3.14

import datetime
from collections.abc import Callable, Sequence
from functools import partial
from importlib.metadata import version
from ipaddress import ip_address, ip_network
from typing import Any, cast, override

import idna
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed448,
    ed25519,
    rsa,
)
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificateIssuerPublicKeyTypes,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

"""
Cnert makes TLS private keys, CSRs, private CAs and certificates.
"""

__version__ = version("cnert")
__title__ = "Cnert"
__description__ = (
    "Cnert makes TLS private keys, CSRs, private CAs and certificates."
)
__uri__ = "https://github.com/maartenq/cnert"
__author__ = "Maarten"
__email__ = "ikmaarten@gmail.com"
__license__ = "MIT or Apache License, Version 2.0"
__copyright__ = "Copyright (c) 2023  Maarten"


# Non-RSA key algorithms, by the name `build_private_key` takes. RSA is
# handled separately: it is the default and the only one that takes
# key_size and public_exponent.
_KEY_BUILDERS: dict[str, Callable[[], CertificateIssuerPrivateKeyTypes]] = {
    "ed25519": ed25519.Ed25519PrivateKey.generate,
    "ed448": ed448.Ed448PrivateKey.generate,
    "secp256r1": partial(ec.generate_private_key, ec.SECP256R1()),
    "secp384r1": partial(ec.generate_private_key, ec.SECP384R1()),
    "secp521r1": partial(ec.generate_private_key, ec.SECP521R1()),
}
KEY_ALGORITHMS: tuple[str, ...] = ("rsa", *_KEY_BUILDERS)

# Edwards keys sign without a separate hash algorithm; every other key
# type requires one.
_EDWARDS_KEYS = (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)

# The hashes usable for an X.509 signature. `cryptography` types this
# set as a module-private union, so cnert keeps its own copy: SHA-1 and
# MD5 are refused outright, and there is no way to sign with them.
_ALLOWED_HASHES = (
    hashes.SHA224,
    hashes.SHA256,
    hashes.SHA384,
    hashes.SHA512,
    hashes.SHA3_224,
    hashes.SHA3_256,
    hashes.SHA3_384,
    hashes.SHA3_512,
)


class _UnsetType:
    """
    Sentinel type: "no signature hash given".

    `None` is a meaningful signature hash (Edwards keys require it), so
    it cannot double as the default.
    """

    @override
    def __repr__(self) -> str:
        return "<unset>"


_UNSET = _UnsetType()


def build_private_key(
    key_size: int | None = None,
    public_exponent: int | None = None,
    algorithm: str = "rsa",
) -> CertificateIssuerPrivateKeyTypes:
    """
    Creates a private key.

    Examples:
        >>> build_private_key()  # 2048-bit RSA
        >>> build_private_key(algorithm="ed25519")
        >>> build_private_key(key_size=1024)

    Parameters:
        key_size: RSA key size, default 2048. RSA only.
        public_exponent: RSA public exponent, default 65537. RSA only.
        algorithm: One of `cnert.KEY_ALGORITHMS`: `rsa` (default),
            `ed25519`, `ed448`, or an EC curve name such as
            `secp256r1`.

    Raises:
        ValueError: If `algorithm` is unknown, or if `key_size` or
            `public_exponent` is given for a non-RSA algorithm.

    Returns:
        A private key of the requested algorithm.
    """
    if algorithm == "rsa":
        return rsa.generate_private_key(
            public_exponent=(
                65537 if public_exponent is None else public_exponent
            ),
            key_size=2048 if key_size is None else key_size,
        )
    if key_size is not None or public_exponent is not None:
        raise ValueError(
            "key_size and public_exponent are RSA-only, but algorithm "
            f"is {algorithm!r}"
        )
    try:
        build = _KEY_BUILDERS[algorithm]
    except KeyError:
        raise ValueError(
            f"unknown algorithm {algorithm!r}; "
            f"pick one of {', '.join(KEY_ALGORITHMS)}"
        ) from None
    return build()


def _signature_hash_for(
    private_key: CertificateIssuerPrivateKeyTypes,
    signature_hash: hashes.HashAlgorithm | _UnsetType | None = _UNSET,
) -> hashes.HashAlgorithm | None:
    """
    Resolve and validate the signature hash for a signing key.

    Parameters:
        private_key: The key that will do the signing.
        signature_hash: The requested hash, `None` for Edwards keys, or
            unset to take the default for the key type.

    Raises:
        ValueError: If a hash is given for an Edwards key, withheld
            for any other key type, or unusable for signatures.

    Returns:
        The hash to sign with, or `None` for an Edwards key.
    """
    is_edwards = isinstance(private_key, _EDWARDS_KEYS)
    if isinstance(signature_hash, _UnsetType):
        return None if is_edwards else hashes.SHA256()
    if is_edwards and signature_hash is not None:
        raise ValueError(
            "Ed25519 and Ed448 keys take no signature hash; pass None"
        )
    if signature_hash is None:
        if is_edwards:
            return None
        raise ValueError(
            f"an {type(private_key).__name__} requires a signature "
            "hash; only Ed25519 and Ed448 sign without one"
        )
    # Not TRY004/TypeError: SHA-1 is a perfectly good HashAlgorithm,
    # it just cannot sign a certificate. That is a value, not a type.
    if not isinstance(signature_hash, _ALLOWED_HASHES):
        raise ValueError(  # noqa: TRY004
            f"{signature_hash.name} cannot sign an X.509 certificate; "
            "use a SHA-2 or SHA-3 hash"
        )
    return signature_hash


def _dedupe_extensions(
    extensions: Sequence[tuple[x509.ExtensionType, bool]],
) -> list[tuple[x509.ExtensionType, bool]]:
    """
    Reduce extension pairs to one per object identifier.

    X.509 forbids two extensions with the same object identifier, and
    `cryptography`'s builders raise on the second one. The last pair for
    an identifier wins, keeping the position of the first, so a
    caller-supplied extension replaces the built-in one it collides
    with.
    """
    by_oid: dict[x509.ObjectIdentifier, tuple[x509.ExtensionType, bool]] = {}
    for extension, critical in extensions:
        by_oid[extension.oid] = (extension, critical)
    return list(by_oid.values())


def _private_key_pem_PKCS1(
    private_key: CertificateIssuerPrivateKeyTypes,
) -> bytes:
    """
    Serialize an RSA private key as PKCS#1 PEM.

    Raises:
        ValueError: If the key is not an RSA key.
    """
    # Not TRY004/TypeError: the caller passed no type here, it read a
    # property that does not apply to the key it already has.
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError(  # noqa: TRY004
            "PKCS#1 is RSA-only; use private_key_pem_PKCS8 for a "
            f"{type(private_key).__name__} key"
        )
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def idna_encode(_string: str) -> str:
    """
    Creates a valid  internationalized domain name

    Parameters:
        _string: Internationalized domain name
    """
    for prefix in ["*.", "."]:
        if _string.startswith(prefix):
            _string = _string[len(prefix) :]
            _bytes = prefix.encode("ascii") + idna.encode(_string, uts46=True)
            return _bytes.decode("ascii")
    return idna.encode(_string, uts46=True).decode("ascii")


def identity_string_to_x509(identity: str) -> x509.GeneralName:
    """
    Creates a x509.GeneralName from a string.

    Parameters:
        identity: IP Address, DNS name or email address.
    """
    try:
        return x509.IPAddress(ip_address(identity))
    except ValueError:
        try:
            return x509.IPAddress(ip_network(identity))
        except ValueError:
            if "@" in identity:
                return x509.RFC822Name(identity)
            return x509.DNSName(idna_encode(identity))


class Freezer:
    """
    Freeze any class such that instantiated objects become immutable.
    """

    _frozen: bool = False

    def __init__(self) -> None:
        self._frozen = True

    @override
    def __delattr__(self, name: str) -> None:
        if self._frozen:
            raise AttributeError("This object is frozen!")
        object.__delattr__(self, name)

    @override
    def __setattr__(self, name: str, value: object) -> None:
        if self._frozen:
            raise AttributeError("This object is frozen!")
        object.__setattr__(self, name, value)


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
        >>> subject_attrs.x509_name()
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

    def __init__(self, **kwargs: str) -> None:
        self._name_oids: list[x509.NameAttribute[str]] = []
        self.dict_: dict[str, str] = {}
        keys = list(kwargs.keys())
        keys.sort()
        for key in keys:
            oid = cast(x509.ObjectIdentifier, getattr(NameOID, key))
            self._name_oids.append(x509.NameAttribute(oid, kwargs[key]))
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
        # type(...).__annotations__ (not __dict__ lookup) keeps this
        # working under PEP 649's lazy annotations on Python >= 3.14.
        return sorted(type(self).__annotations__.keys())

    @override
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NameAttrs):
            return NotImplemented
        return self.dict_ == other.dict_

    @override
    def __hash__(self) -> int:
        # Instances are frozen, so hashing by content is safe.
        return hash(tuple(self.dict_.items()))

    @override
    def __str__(self) -> str:
        return self.x509_name().rfc4514_string()

    @override
    def __repr__(self) -> str:
        args = ", ".join(f'{x[0]}="{x[1]}"' for x in self.dict_.items())
        return f"NameAttrs({args})"


class _CertBuilder:
    """
    Builds and signs a X509 Certificate.
    """

    builder: x509.CertificateBuilder

    def __init__(self) -> None:
        self.builder = x509.CertificateBuilder()

    @staticmethod
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
        """
        Create X509.KeyUsage objects.
        """
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

    def _ca_extensions(self) -> list[tuple[x509.ExtensionType, bool]]:
        """
        CA key usage.
        """
        return [
            (
                self._key_usage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                ),
                True,
            ),
        ]

    def _leaf_cert_extensions(
        self,
    ) -> list[tuple[x509.ExtensionType, bool]]:
        """
        Leaf key usage and extended key usage.
        """
        return [
            (self._key_usage(), True),
            (
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                        ExtendedKeyUsageOID.SERVER_AUTH,
                        ExtendedKeyUsageOID.CODE_SIGNING,
                    ]
                ),
                True,
            ),
        ]

    @staticmethod
    def _subject_alt_name_extension(
        *sans: str,
    ) -> tuple[x509.ExtensionType, bool]:
        """
        Subject Alternative Name extension.

        Parameters:
            sans: Subject Alternative Names as positional arguments.
        """
        return (
            x509.SubjectAlternativeName(
                [identity_string_to_x509(san) for san in sans]
            ),
            True,
        )

    @staticmethod
    def _authority_key_identifier_extension(
        issuer_public_key: CertificateIssuerPublicKeyTypes,
    ) -> tuple[x509.ExtensionType, bool]:
        """
        Authority Key Identifier extension.

        Parameters:
            issuer_public_key: Issuer Public key
        """
        return (
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_public_key
            ),
            False,
        )

    def build(
        self,
        sans: tuple[str, ...],
        subject_attrs_X509_name: x509.Name,
        issuer_attrs_X509_name: x509.Name,
        serial_number: int,
        not_valid_before: datetime.datetime,
        not_valid_after: datetime.datetime,
        is_ca: bool,
        public_key: CertificateIssuerPublicKeyTypes,
        issuer_public_key: CertificateIssuerPublicKeyTypes | None = None,
        path_length: int | None = None,
        extensions: Sequence[tuple[x509.ExtensionType, bool]] = (),
    ) -> None:
        """
        Does the Certificate building.

        Parameters:
            sans: Subject Alternative Names as positional arguments.
            subject_attrs_X509_name: Subject Attributes Names.
            issuer_attrs_X509_name: Issuer Atributes Names.
            serial_number: Serial number.
            not_valid_before: Not valid before date.
            not_valid_after: Note valid after date.
            is_ca: Add CA extension.
            public_key: Public key for the certificate.
            issuer_public_key: Issuer public key.
            path_length: Max path length.
            extensions: Extra `(extension, critical)` pairs. One that
                collides with a built-in extension replaces it.
        """
        self.builder = (
            self.builder.subject_name(subject_attrs_X509_name)
            .issuer_name(issuer_attrs_X509_name)
            .public_key(public_key)
            .serial_number(serial_number)
            .not_valid_before(not_valid_before)
            .not_valid_after(not_valid_after)
        )
        built_in: list[tuple[x509.ExtensionType, bool]] = [
            (x509.SubjectKeyIdentifier.from_public_key(public_key), False),
            (
                x509.BasicConstraints(ca=is_ca, path_length=path_length),
                True,
            ),
        ]
        if issuer_public_key is not None:
            built_in.append(
                self._authority_key_identifier_extension(issuer_public_key)
            )
        built_in.extend(
            self._ca_extensions() if is_ca else self._leaf_cert_extensions()
        )
        if sans:
            built_in.append(self._subject_alt_name_extension(*sans))
        for extension, critical in _dedupe_extensions(
            [*built_in, *extensions]
        ):
            self.builder = self.builder.add_extension(
                extension, critical=critical
            )

    def sign(
        self,
        private_key: CertificateIssuerPrivateKeyTypes,
        signature_hash: hashes.HashAlgorithm | _UnsetType | None = _UNSET,
    ) -> x509.Certificate:
        return self.builder.sign(
            private_key=private_key,
            algorithm=cast(
                "Any", _signature_hash_for(private_key, signature_hash)
            ),
        )


class Cert:
    """
    A Cert object.

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

    sans: tuple[str, ...]
    subject_attrs: NameAttrs
    issuer_attrs: NameAttrs
    parent: Cert | None
    not_valid_before: datetime.datetime
    not_valid_after: datetime.datetime
    serial_number: int
    path_length: int
    is_ca: bool
    private_key: CertificateIssuerPrivateKeyTypes
    certificate: x509.Certificate
    pem: bytes

    def __init__(
        self,
        *sans: str,
        subject_attrs: NameAttrs,
        issuer_attrs: NameAttrs,
        not_valid_before: datetime.datetime | None = None,
        not_valid_after: datetime.datetime | None = None,
        serial_number: int | None = None,
        parent: Cert | None = None,
        private_key: CertificateIssuerPrivateKeyTypes | None = None,
        signature_hash: hashes.HashAlgorithm | _UnsetType | None = _UNSET,
        extensions: Sequence[tuple[x509.ExtensionType, bool]] = (),
        path_length: int = 0,
        is_ca: bool = False,
    ) -> None:
        """
        Initialize a Cert object.

        Parameters:
            sans: Subject Alternative Names as positional arguments
            subject_attrs: Subject Name Attributes
            issuer_attrs: Issure Name Attributes
            not_valid_before: CA not valid before date
            not_valid_after: CA not valid after date
            serial_number: Serial number
            parent: Certificate of CA.
            private_key: Private key; generated when omitted.
            signature_hash: Signature hash algorithm. Defaults to
                SHA-256, or to `None` when the signing key is an
                Edwards key, which takes no hash.
            extensions: Extra `(extension, critical)` pairs. One that
                collides with a built-in extension replaces it
                wholesale.
            path_length: Path length
            is_ca: if CA

        Raises:
            ValueError: If `signature_hash` does not suit the signing
                key. See
                [`cnert.build_private_key`][cnert.build_private_key].
        """
        if not_valid_before is None:
            not_valid_before = datetime.datetime.now(datetime.UTC)

        if not_valid_after is None:
            not_valid_after = not_valid_before + datetime.timedelta(weeks=13)

        if serial_number is None:
            serial_number = x509.random_serial_number()

        if private_key is None:
            self.private_key = build_private_key()
        else:
            self.private_key = private_key

        self.sans = sans
        self.subject_attrs = subject_attrs
        self.issuer_attrs = issuer_attrs
        self.parent = parent
        self.not_valid_before = not_valid_before
        self.not_valid_after = not_valid_after
        self.serial_number = serial_number
        self.path_length = path_length
        self.is_ca = is_ca
        self._build_certificate(signature_hash, extensions)

    def _build_certificate(
        self,
        signature_hash: hashes.HashAlgorithm | _UnsetType | None = _UNSET,
        extensions: Sequence[tuple[x509.ExtensionType, bool]] = (),
    ) -> None:
        cert_builder = _CertBuilder()
        cert_builder.build(
            sans=self.sans,
            subject_attrs_X509_name=self.subject_attrs.x509_name(),
            issuer_attrs_X509_name=self.issuer_attrs.x509_name(),
            serial_number=self.serial_number,
            not_valid_before=self.not_valid_before,
            not_valid_after=self.not_valid_after,
            is_ca=self.is_ca,
            public_key=self.public_key,
            issuer_public_key=(
                self.parent.public_key if self.parent else None
            ),
            path_length=None if not self.is_ca else self.path_length,
            extensions=extensions,
        )
        self.certificate = cert_builder.sign(
            self.parent.private_key if self.parent else self.private_key,
            signature_hash,
        )
        self.pem = self.certificate.public_bytes(serialization.Encoding.PEM)

    @property
    def private_key_pem_PKCS1(self) -> bytes:
        """
        Examples:
            >>> cert = CA().issue_cert()
            >>> cert.private_key_pem_PKCS1
            b'-----begin rsa private key-----
            ...


        Raises:
            ValueError: If the key is not an RSA key. PKCS#1 is
                RSA-only.

        Returns:
            PEM encoded serialized key in TraditionalOpenSSL format.
        """
        return _private_key_pem_PKCS1(self.private_key)

    @property
    def private_key_pem_PKCS8(self) -> bytes:
        """
        Examples:
            >>> cert = CA().issue_cert()
            >>> cert.private_key_pem_PKCS8
            b'-----BEGIN PRIVATE KEY-----
            ...

        Returns:
            PEM encoded serialized key in PKCS8 format.
        """
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def public_key(self) -> CertificateIssuerPublicKeyTypes:
        """
        Examples:
            >>> cert = cnert.CA().issue_cert()
            >>> cert.public_key
            <cryptography.hazmat.bindings._rust.openssl.rsa.RSAPublicKey
            object at 0x1014e4e10>

        Returns:
            The public key matching this certificate's private key.
        """
        return self.private_key.public_key()

    @property
    def public_key_pem(self) -> bytes:
        """
        Examples:
            >>> cert = CA().issue_cert()
            >>> cert.public_key_pem
            b'-----BEGIN PUBLIC KEY-----
            ...


        Returns:
            PEM encoded serialized key in RSAPublicKey format.
        """
        return self.public_key.public_bytes(
            serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def MD5(self) -> str:
        """
        Examples:
            >>> cert = cnert.CA().issue_cert()
            >>> cert.MD5
            'A03D37486DD47BE3E9C7EC1624073856'

        Returns:
            MD5 Fingerprint string in hexadecimal and upper case.
        """
        return bytes.hex(
            self.certificate.fingerprint(hashes.MD5()),  # noqa: S303
        ).upper()

    @property
    def SHA1(self) -> str:
        """
        Examples:
            >>> cert = cnert.CA().issue_cert()
            >>> cert.SHA1
            '9E0A06CFB37B352FDA5B2226E6D631CF07D5D185'

        Returns:
            SHA1 Fingerprint string in hexadecimal and upper case.
        """
        return bytes.hex(
            self.certificate.fingerprint(hashes.SHA1()),  # noqa: S303
        ).upper()

    @property
    def SHA256(self) -> str:
        """
        Examples:
            >>> cert = cnert.CA().issue_cert()
            >>> cert.SHA256
            '68307A6CBE2804038DF85FB53AEE96AB47EA81439AB2E059DDDEA9F901097D84'

        Returns:
            SHA256 Fingerprint string in hexadecimal and upper case.
        """
        return bytes.hex(self.certificate.fingerprint(hashes.SHA256())).upper()

    @property
    def subject_key_identifier_digest(self) -> str:
        """
        Examples:
            >>> cert = cnert.CA().issue_cert()
            >>> cert.subject_key_identifier_digest
            '8F85C564F62E39D5A5CA346CA26AAE67029B671E'

        Returns:
            The binary value of the subject key identifier in hexadecimal
            and upper case.
        """
        ext = self.certificate.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        )
        return bytes.hex(ext.value.key_identifier).upper()

    @property
    def authority_key_identifier_digest(self) -> str | None:
        """
        Examples:
            >>> cert = cnert.CA().issue_cert()
            >>> cert.authority_key_identifier_digest
            '8F85C564F62E39D5A5CA346CA26AAE67029B671E'

        Returns:
            The binary value of the authority key identifier in hexadecimal
            and upper case or None when certificate has no
            subject key identifier extension.
        """
        try:
            ext = self.certificate.extensions.get_extension_for_class(
                x509.AuthorityKeyIdentifier
            )
            if ext.value.key_identifier is None:
                return None
            return bytes.hex(ext.value.key_identifier).upper()
        except x509.ExtensionNotFound:
            return None

    @override
    def __str__(self) -> str:
        return f"Certificate {self.subject_attrs}"


class CSR:
    """
    A CSR object.

    Examples:
        >>> csr = cnert.CSR()

    Parameters:
        sans: Subject Alternative Names as positional arguments
        subject_attrs: Subject Name Attributes
        private_key: Private key; generated when omitted.
        signature_hash: Signature hash algorithm. Defaults to SHA-256,
            or to `None` for an Edwards key, which takes no hash.
        extensions: Extra `(extension, critical)` pairs. One that
            collides with a built-in extension replaces it wholesale.

    """

    sans: tuple[str, ...]
    subject_attrs: NameAttrs
    private_key: CertificateIssuerPrivateKeyTypes
    CSR: x509.CertificateSigningRequest
    pem: bytes

    def __init__(
        self,
        *sans: str,
        subject_attrs: NameAttrs | None = None,
        private_key: CertificateIssuerPrivateKeyTypes | None = None,
        signature_hash: hashes.HashAlgorithm | _UnsetType | None = _UNSET,
        extensions: Sequence[tuple[x509.ExtensionType, bool]] = (),
    ) -> None:
        self.sans = sans

        if subject_attrs is None:
            if sans:
                subject_attrs = NameAttrs(COMMON_NAME=sans[0])
            else:
                subject_attrs = NameAttrs(COMMON_NAME="example.com")
        self.subject_attrs = subject_attrs

        if private_key is None:
            self.private_key = build_private_key()
        else:
            self.private_key = private_key

        self._csr_builder: x509.CertificateSigningRequestBuilder = (
            x509.CertificateSigningRequestBuilder().subject_name(
                subject_attrs.x509_name()
            )
        )
        self.CSR = self._gen_csr(signature_hash, extensions)

    def _subject_alt_name_extension(
        self,
    ) -> tuple[x509.ExtensionType, bool]:
        return (
            x509.SubjectAlternativeName(
                [identity_string_to_x509(san) for san in self.sans]
            ),
            False,
        )

    def _gen_csr(
        self,
        signature_hash: hashes.HashAlgorithm | _UnsetType | None = _UNSET,
        extensions: Sequence[tuple[x509.ExtensionType, bool]] = (),
    ) -> x509.CertificateSigningRequest:
        built_in: list[tuple[x509.ExtensionType, bool]] = []
        if self.sans:
            built_in.append(self._subject_alt_name_extension())
        for extension, critical in _dedupe_extensions(
            [*built_in, *extensions]
        ):
            self._csr_builder = self._csr_builder.add_extension(
                extension, critical=critical
            )
        csr = self._csr_builder.sign(
            private_key=self.private_key,
            algorithm=cast(
                "Any",
                _signature_hash_for(self.private_key, signature_hash),
            ),
        )
        self.pem = csr.public_bytes(serialization.Encoding.PEM)
        return csr

    @property
    def private_key_pem_PKCS1(self) -> bytes:
        """
        Raises:
            ValueError: If the key is not an RSA key. PKCS#1 is
                RSA-only.

        Returns:
            PEM encoded serialized key in TraditionalOpenSSL format.
        """
        return _private_key_pem_PKCS1(self.private_key)

    @property
    def private_key_pem_PKCS8(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def public_key(self) -> CertificateIssuerPublicKeyTypes:
        return self.private_key.public_key()

    @override
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
        subject_attrs: Subject Name Attributes.
        subject_attrs: Issuer Name Attributes.
        path_length: Maximum path length certificates subordinate.
        not_valid_before: CA not valid before date.
        not_valid_after: CA not valid after date.
        parent: Parent of CA.
        intermediate_num: Number of intermediates.
        signature_hash: Signature hash algorithm for the CA's own
            certificate. Defaults to SHA-256, or to `None` for an
            Edwards key, which takes no hash.
        extensions: Extra `(extension, critical)` pairs for the CA's
            own certificate. One that collides with a built-in
            extension replaces it wholesale.
        private_key: Private key for the CA's own certificate;
            generated when omitted. Reusing one key across a chain is
            allowed, and is how a key-reuse fixture is built.
    """

    intermediate_num: int
    parent: CA | None
    cert: Cert

    def __init__(
        self,
        subject_attrs: NameAttrs | None = None,
        issuer_attrs: NameAttrs | None = None,
        path_length: int = 9,
        not_valid_before: datetime.datetime | None = None,
        not_valid_after: datetime.datetime | None = None,
        serial_number: int | None = None,
        parent: CA | None = None,
        intermediate_num: int = 0,
        signature_hash: hashes.HashAlgorithm | _UnsetType | None = _UNSET,
        extensions: Sequence[tuple[x509.ExtensionType, bool]] = (),
        private_key: CertificateIssuerPrivateKeyTypes | None = None,
    ) -> None:
        self.intermediate_num = intermediate_num
        self.parent = parent

        if subject_attrs is None:
            subject_attrs = NameAttrs(ORGANIZATION_NAME="Root CA")

        if issuer_attrs is None:
            issuer_attrs = subject_attrs

        self.cert = Cert(
            subject_attrs=subject_attrs,
            issuer_attrs=issuer_attrs,
            path_length=path_length,
            not_valid_before=not_valid_before,
            not_valid_after=not_valid_after,
            serial_number=serial_number,
            parent=(self.parent.cert if self.parent is not None else None),
            signature_hash=signature_hash,
            extensions=extensions,
            private_key=private_key,
            is_ca=True,
        )

    @override
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
        subject_attrs: NameAttrs | None = None,
        not_valid_before: datetime.datetime | None = None,
        not_valid_after: datetime.datetime | None = None,
        serial_number: int | None = None,
        signature_hash: hashes.HashAlgorithm | _UnsetType | None = _UNSET,
        extensions: Sequence[tuple[x509.ExtensionType, bool]] = (),
        private_key: CertificateIssuerPrivateKeyTypes | None = None,
    ) -> CA:
        """
        Issues an intermediate CA.

        Parameters:
            subject_attrs: Subject Name Attributes.
            not_valid_before: Intermediate not valid before date.
            not_valid_after: Intermediate not valid after date.
            serial_number: Serial number.
            signature_hash: Signature hash algorithm for the
                intermediate's certificate.
            extensions: Extra `(extension, critical)` pairs.
            private_key: Private key for the intermediate; generated
                when omitted. The intermediate is still signed by this
                CA's key.

        Raises:
            ValueError: If this CA's path length is 0.

        Returns:
            A CA object.
        """
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
            serial_number=serial_number,
            parent=self,
            intermediate_num=intermediate_num,
            signature_hash=signature_hash,
            extensions=extensions,
            private_key=private_key,
        )

    def issue_cert(
        self,
        *sans: str,
        subject_attrs: NameAttrs | None = None,
        not_valid_before: datetime.datetime | None = None,
        not_valid_after: datetime.datetime | None = None,
        serial_number: int | None = None,
        csr: CSR | None = None,
        signature_hash: hashes.HashAlgorithm | _UnsetType | None = _UNSET,
        extensions: Sequence[tuple[x509.ExtensionType, bool]] = (),
        private_key: CertificateIssuerPrivateKeyTypes | None = None,
    ) -> Cert:
        """
        Issues a certificate

        Examples:
            >>> ca = CA()
            >>> ca.issue_cert()
            <cnert.Cert at 0x107f87f50>

        Parameters:
            sans: Subject Alternative Names as positional arguments.
            subject_attrs: Subject Name Attributes.
            not_valid_before: Certificate not valid before date.
            not_valid_after: Certificate not valid after date.
            csr: A CSR object.
            signature_hash: Signature hash algorithm. Defaults to
                SHA-256, or to `None` when this CA's key is an Edwards
                key, which takes no hash.
            extensions: Extra `(extension, critical)` pairs. One that
                collides with a built-in extension replaces it
                wholesale.
            private_key: Private key for the certificate; generated
                when omitted. It is the certificate's subject key
                only: the signature always comes from this CA's key.
                A `csr` carries its own key, so the two are mutually
                exclusive.

        Raises:
            ValueError: If both `private_key` and `csr` are given.

        Returns:
            A Cert object.

        """
        if csr is not None and private_key is not None:
            raise ValueError(
                "pass either private_key or csr, not both: a CSR "
                "already carries a key"
            )
        if csr:
            sans = csr.sans
            subject_attrs = csr.subject_attrs
            private_key = csr.private_key
        else:
            if subject_attrs is None:
                if sans:
                    subject_attrs = NameAttrs(COMMON_NAME=sans[0])
                else:
                    subject_attrs = NameAttrs(COMMON_NAME="example.com")
        return Cert(
            *sans,
            subject_attrs=subject_attrs,
            issuer_attrs=self.cert.subject_attrs,
            not_valid_before=not_valid_before,
            not_valid_after=not_valid_after,
            serial_number=serial_number,
            parent=self.cert,
            private_key=private_key,
            signature_hash=signature_hash,
            extensions=extensions,
        )


# Deprecated alias: Cert was named _Cert through 0.10.x although public
# API (`CA.issue_cert`) returned it. Kept for backwards compatibility.
_Cert = Cert
