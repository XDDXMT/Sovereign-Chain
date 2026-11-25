"""Direct-issuer X.509 profile used by SC-EE-3, with a full, direct CRL."""

import datetime
import hashlib
import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import (
    CRLEntryExtensionOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
)

# SHA-256 of public SubjectPublicKeyInfo from previously distributed key sets.
# Using the public key rather than a certificate serial also covers reissuance.
RETIRED_KEYS = frozenset(
    {
        "2044723b72a7fcc1f93fbd6842ce3ad6c05b9483bca11de0fd09be0e3756ed92",
        "22d5c97901ebde9c9a3948572dffb8faddc960a6e50ee374e7b8b72d5ab135a2",
        "25b818b937aa2970a5e1e0a691ecb4e619208855eb0a240d76c44543a141ba9f",
        "2aff8bde1cec7a9e668acbe0408e27feb8ea51cdfc452f2c1746436e3c3da398",
        "30f44e47a51f90f522908e081919d5356679d761a3e7a76d4fe446d30035fb41",
        "441f4a2d61ff18a695fd26cab98218a7a517e8873f7e1f72e874f8a670852eeb",
        "58094cc127b03dd558f84c6f2b0c0dd9f5956e515da0fa330cdf407dcde38d06",
        "6d5ca369e4df11e32de989e428eb64a117eac489ff8b5eb880a0e65236ebbbd5",
        "7325d58c58d84118df869b05a4ea2c3240c32d00060bea660aa3b80dc126813b",
        "96834201d8b494cb74b2442fb3116d473fc948389b3eddec573b390ab4326b48",
        "99a55544fe4fd56f48c73914fd98c6edd0ef2e1af8eab4e4932e71261eb43d7c",
        "b79fb7828d4ebdc7e57dc5e98928c6763bc8199021303ac02682121cf1a0afba",
        "bf109d62dbb989bdfd89a841a4647eb4c8c8652972219825e521c261cbbcd018",
        "d9f4c4cedc779fe20198e4c4fd158bfdda7a7737097c45b2649f7608e9e59c7d",
        "ec9741b7f9692731eb632f5bef8daee725dcc58e9aa820ea2ead50147b6610cc",
    }
)
UTC = datetime.timezone.utc
FROM_ENV = object()
MAX_CRL_BYTES = 8 * 1024 * 1024
CA_CRITICAL = {ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE}
LEAF_CRITICAL = CA_CRITICAL | {
    ExtensionOID.EXTENDED_KEY_USAGE,
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
}
CA_RESTRICTIONS = {
    ExtensionOID.NAME_CONSTRAINTS,
    ExtensionOID.POLICY_CONSTRAINTS,
    ExtensionOID.INHIBIT_ANY_POLICY,
    ExtensionOID.POLICY_MAPPINGS,
    ExtensionOID.EXTENDED_KEY_USAGE,
}


class CertificateValidationError(ValueError):
    pass


def public_key_id(key):
    return hashlib.sha256(
        key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()


def check_key(key):
    if public_key_id(key) in RETIRED_KEYS:
        raise CertificateValidationError(
            "retired distribution key: rotate the CA and endpoint credentials"
        )


def verify_private_key_matches_certificate(private_key, cert):
    check_key(cert.public_key())
    if public_key_id(private_key.public_key()) != public_key_id(cert.public_key()):
        raise CertificateValidationError("private key does not match certificate")


def _verify_signature(pub, signed):
    if isinstance(pub, ed25519.Ed25519PublicKey):
        args = ()
    else:
        digest = signed.signature_hash_algorithm
        if not isinstance(digest, (hashes.SHA256, hashes.SHA384, hashes.SHA512)):
            raise CertificateValidationError("unsupported signature digest")
        params = signed.signature_algorithm_parameters
        if (
            isinstance(pub, rsa.RSAPublicKey)
            and pub.key_size >= 2048
            and isinstance(params, padding.AsymmetricPadding)
        ):
            args = (params, digest)
        elif (
            isinstance(pub, ec.EllipticCurvePublicKey)
            and pub.key_size >= 256
            and isinstance(params, ec.ECDSA)
        ):
            args = (params,)
        else:
            raise CertificateValidationError(
                "unsupported issuer key or signature algorithm"
            )
    data = (
        signed.tbs_certificate_bytes
        if isinstance(signed, x509.Certificate)
        else signed.tbs_certlist_bytes
    )
    try:
        pub.verify(signed.signature, data, *args)
    except InvalidSignature as exc:
        raise CertificateValidationError("invalid issuer signature") from exc


def _required(obj, extension):
    try:
        return obj.extensions.get_extension_for_class(extension).value
    except x509.ExtensionNotFound as exc:
        raise CertificateValidationError(f"missing {extension.__name__}") from exc


def _check_profile(cert, allowed, now):
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise CertificateValidationError("certificate outside validity period")
    for ext in cert.extensions:
        if ext.critical and ext.oid not in allowed:
            raise CertificateValidationError(
                f"unsupported critical extension {ext.oid.dotted_string}"
            )
    check_key(cert.public_key())


def validate_ca_certificate(ca_cert, issuer_cert=None, now=None):
    now = now or datetime.datetime.now(UTC)
    _check_profile(ca_cert, CA_CRITICAL, now)
    if any(ext.oid in CA_RESTRICTIONS for ext in ca_cert.extensions):
        raise CertificateValidationError(
            "issuer constraints are outside the direct-CA profile"
        )
    if (
        not _required(ca_cert, x509.BasicConstraints).ca
        or not _required(ca_cert, x509.KeyUsage).key_cert_sign
    ):
        raise CertificateValidationError(
            "issuer is not authorized to sign certificates"
        )
    if issuer_cert is not None:
        validate_ca_certificate(issuer_cert, now=now)
        if (
            ca_cert.subject != ca_cert.issuer
            and _required(issuer_cert, x509.BasicConstraints).path_length == 0
        ):
            raise CertificateValidationError("issuer cannot sign a subordinate CA")
        if ca_cert.issuer != issuer_cert.subject:
            raise CertificateValidationError("CA issuer name mismatch")
        _verify_signature(issuer_cert.public_key(), ca_cert)


def require_identity(cert, allowed_names):
    san = _required(cert, x509.SubjectAlternativeName)
    dns = {name.lower() for name in san.get_values_for_type(x509.DNSName)}
    ips = set(san.get_values_for_type(x509.IPAddress))
    for name in allowed_names:
        name = name.strip()
        if not name:
            continue
        try:
            ip = ipaddress.ip_address(name)
        except ValueError:
            if name.isascii() and name.lower() in dns:
                return
        else:
            if ip in ips:
                return
    raise CertificateValidationError("certificate identity is not authorized")


def require_crl_setting(name):
    value = os.getenv(name, "0").strip().lower()
    if value not in {"0", "1", "false", "true"}:
        raise ValueError(f"{name} must be 0, 1, false, or true")
    return value in {"1", "true"}


def read_crl(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_CRL_BYTES + 1)
    if len(data) > MAX_CRL_BYTES:
        raise CertificateValidationError("CRL exceeds the supported size")
    return data


@dataclass(frozen=True)
class Revocations:
    authority: str
    since: datetime.datetime
    until: datetime.datetime
    serials: frozenset
    number: int | None

    def check(self, cert, issuer, now):
        if (
            public_key_id(issuer.public_key()) != self.authority
            or not self.since <= now < self.until
        ):
            raise CertificateValidationError(
                "CRL belongs to another authority or is outside its validity period"
            )
        if cert.serial_number in self.serials:
            raise CertificateValidationError("certificate has been revoked")


def parse_crl(data, issuer):
    if not _required(issuer, x509.KeyUsage).crl_sign:
        raise CertificateValidationError("issuer cannot sign CRLs")
    crl = (
        x509.load_pem_x509_crl(data)
        if data.lstrip().startswith(b"-----BEGIN")
        else x509.load_der_x509_crl(data)
    )
    if crl.issuer != issuer.subject or crl.next_update_utc is None:
        raise CertificateValidationError("CRL issuer or validity window is invalid")
    # Only complete, direct, all-reasons lists belong to this profile. Unknown
    # scope must never be interpreted as evidence of a non-revoked credential.
    for ext in crl.extensions:
        if ext.critical or ext.oid not in {
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            ExtensionOID.CRL_NUMBER,
        }:
            raise CertificateValidationError("unsupported CRL scope or extension")
    try:
        aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    except x509.ExtensionNotFound:
        aki = None
    if aki is not None:
        try:
            ski = issuer.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value.digest
        except x509.ExtensionNotFound:
            ski = x509.SubjectKeyIdentifier.from_public_key(issuer.public_key()).digest
        if aki.key_identifier is not None and aki.key_identifier != ski:
            raise CertificateValidationError("CRL authority key identifier mismatch")
        if aki.authority_cert_serial_number is not None and (
            aki.authority_cert_serial_number != issuer.serial_number
            or x509.DirectoryName(issuer.issuer)
            not in (aki.authority_cert_issuer or ())
        ):
            raise CertificateValidationError("CRL authority certificate mismatch")
    try:
        number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound:
        number = None
    _verify_signature(issuer.public_key(), crl)
    serials = set()
    for entry in crl:
        if entry.serial_number in serials:
            raise CertificateValidationError("duplicate revocation entry")
        for ext in entry.extensions:
            if ext.critical or ext.oid not in {
                CRLEntryExtensionOID.CRL_REASON,
                CRLEntryExtensionOID.INVALIDITY_DATE,
            }:
                raise CertificateValidationError("unsupported CRL entry extension")
            if (
                isinstance(ext.value, x509.CRLReason)
                and ext.value.reason == x509.ReasonFlags.remove_from_crl
            ):
                raise CertificateValidationError("unexpected removal in a complete CRL")
        serials.add(entry.serial_number)
    return Revocations(
        public_key_id(issuer.public_key()),
        crl.last_update_utc,
        crl.next_update_utc,
        frozenset(serials),
        number,
    )


def verify_certificate_signature(cert, issuer_cert):
    _verify_signature(issuer_cert.public_key(), cert)


def check_certificate_revocation(cert, issuer_cert, *, now=None, revocations=FROM_ENV):
    now = now or datetime.datetime.now(UTC)
    if revocations is FROM_ENV:
        path = os.getenv("SC_CRL_FILE")
        required = require_crl_setting("SC_REQUIRE_CRL")
        if required and not path:
            raise CertificateValidationError("CRL required but no path configured")
        revocations = parse_crl(read_crl(path), issuer_cert) if path else None
    if revocations is not None:
        revocations.check(cert, issuer_cert, now)


def validate_peer_certificate(
    cert, ca_cert, role, expected_identity=None, now=None, *, revocations=FROM_ENV
):
    if role not in {"server", "client"}:
        raise ValueError("invalid peer role")
    now = now or datetime.datetime.now(UTC)
    validate_ca_certificate(ca_cert, now=now)
    _check_profile(cert, LEAF_CRITICAL, now)
    if cert.issuer != ca_cert.subject:
        raise CertificateValidationError("certificate issuer name mismatch")
    key_usage = _required(cert, x509.KeyUsage)
    if (
        _required(cert, x509.BasicConstraints).ca
        or not key_usage.digital_signature
        or key_usage.key_cert_sign
        or key_usage.crl_sign
    ):
        raise CertificateValidationError("invalid endpoint key usage")
    usage = (
        ExtendedKeyUsageOID.SERVER_AUTH
        if role == "server"
        else ExtendedKeyUsageOID.CLIENT_AUTH
    )
    if usage not in _required(cert, x509.ExtendedKeyUsage):
        raise CertificateValidationError("certificate role mismatch")
    if not isinstance(cert.public_key(), ed25519.Ed25519PublicKey):
        raise CertificateValidationError("endpoint authentication requires Ed25519")
    _verify_signature(ca_cert.public_key(), cert)
    if expected_identity is not None:
        require_identity(cert, [expected_identity])
    check_certificate_revocation(cert, ca_cert, now=now, revocations=revocations)
    return cert
