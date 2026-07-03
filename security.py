"""Shared security primitives for the Sovereign-Chain protocol."""

import datetime
import ipaddress
import os
import struct
import threading

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import ExtendedKeyUsageOID


PROTO_VER = b"SC-EE-2"
CIPHER_SUITE = b"X25519-Ed25519-CHACHA20POLY1305-HKDFSHA256"
MAX_FRAME_SIZE = 1_000_000


class CertificateValidationError(ValueError):
    pass


class SequenceValidationError(ValueError):
    pass


def hkdf(ikm, info, length=64):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(ikm)


def nonce_from_seq(seq: int, label: bytes):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(label)
    return digest.finalize()[:4] + struct.pack(">Q", seq)


def _verify_signature(public_key, signature, signed_data, hash_algorithm, parameters=None):
    try:
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, signed_data)
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                signed_data,
                parameters
                if isinstance(parameters, padding.AsymmetricPadding)
                else padding.PKCS1v15(),
                hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature,
                signed_data,
                parameters if isinstance(parameters, ec.ECDSA) else ec.ECDSA(hash_algorithm),
            )
        else:
            raise CertificateValidationError("unsupported certificate signing key")
    except InvalidSignature as exc:
        raise CertificateValidationError("certificate signature is invalid") from exc


def verify_certificate_signature(cert, issuer_cert):
    _verify_signature(
        issuer_cert.public_key(),
        cert.signature,
        cert.tbs_certificate_bytes,
        cert.signature_hash_algorithm,
        getattr(cert, "signature_algorithm_parameters", None),
    )


def check_certificate_revocation(cert, issuer_cert):
    crl_path = os.getenv("SC_CRL_FILE")
    required = os.getenv("SC_REQUIRE_CRL") == "1"
    if not crl_path:
        if required:
            raise CertificateValidationError("CRL checking is required but SC_CRL_FILE is unset")
        return

    try:
        with open(crl_path, "rb") as crl_file:
            data = crl_file.read()
        try:
            crl = x509.load_pem_x509_crl(data)
        except ValueError:
            crl = x509.load_der_x509_crl(data)
    except (OSError, ValueError) as exc:
        raise CertificateValidationError(f"failed to load CRL: {exc}") from exc

    if crl.issuer != issuer_cert.subject:
        raise CertificateValidationError("CRL issuer does not match certificate issuer")
    _verify_signature(
        issuer_cert.public_key(),
        crl.signature,
        crl.tbs_certlist_bytes,
        crl.signature_hash_algorithm,
        getattr(crl, "signature_algorithm_parameters", None),
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    last_update = getattr(crl, "last_update_utc", None) or _utc(crl.last_update)
    next_update_value = getattr(crl, "next_update_utc", None)
    if next_update_value is None and crl.next_update is not None:
        next_update_value = _utc(crl.next_update)
    if now < last_update or next_update_value is None or now > next_update_value:
        raise CertificateValidationError("CRL is not currently valid")
    if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
        raise CertificateValidationError("certificate has been revoked")


def _utc(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value.astimezone(datetime.timezone.utc)


def _validate_time(cert, now):
    not_before = getattr(cert, "not_valid_before_utc", None) or _utc(cert.not_valid_before)
    not_after = getattr(cert, "not_valid_after_utc", None) or _utc(cert.not_valid_after)
    if now < not_before:
        raise CertificateValidationError("certificate is not yet valid")
    if now > not_after:
        raise CertificateValidationError("certificate has expired")


def _validate_identity(cert, expected_identity):
    if not expected_identity:
        return

    try:
        expected_ip = ipaddress.ip_address(expected_identity)
    except ValueError:
        expected_ip = None

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as exc:
        raise CertificateValidationError("peer certificate lacks SubjectAlternativeName") from exc
    if expected_ip is not None:
        matches = expected_ip in san.get_values_for_type(x509.IPAddress)
    else:
        matches = expected_identity.lower() in {
            name.lower() for name in san.get_values_for_type(x509.DNSName)
        }
    if not matches:
        raise CertificateValidationError(
            f"certificate identity does not match {expected_identity}"
        )


def validate_ca_certificate(ca_cert, issuer_cert=None, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    _validate_time(ca_cert, now)
    try:
        constraints = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = ca_cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise CertificateValidationError("CA certificate lacks required constraints") from exc
    if not constraints.ca or not usage.key_cert_sign:
        raise CertificateValidationError("issuer certificate is not authorized as a CA")
    if issuer_cert is not None:
        if ca_cert.issuer != issuer_cert.subject:
            raise CertificateValidationError("CA issuer name mismatch")
        verify_certificate_signature(ca_cert, issuer_cert)


def validate_peer_certificate(cert, ca_cert, role, expected_identity=None, now=None):
    if role not in {"server", "client"}:
        raise ValueError("role must be 'server' or 'client'")

    now = now or datetime.datetime.now(datetime.timezone.utc)
    validate_ca_certificate(ca_cert, now=now)
    _validate_time(cert, now)
    if cert.issuer != ca_cert.subject:
        raise CertificateValidationError("certificate issuer name mismatch")
    verify_certificate_signature(cert, ca_cert)
    check_certificate_revocation(cert, ca_cert)

    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise CertificateValidationError("peer certificate lacks BasicConstraints") from exc
    if constraints.ca:
        raise CertificateValidationError("a CA certificate cannot authenticate a peer")

    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise CertificateValidationError("peer certificate lacks KeyUsage") from exc
    if not usage.digital_signature:
        raise CertificateValidationError("peer certificate cannot create signatures")

    required_eku = (
        ExtendedKeyUsageOID.SERVER_AUTH if role == "server"
        else ExtendedKeyUsageOID.CLIENT_AUTH
    )
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise CertificateValidationError("peer certificate lacks ExtendedKeyUsage") from exc
    if required_eku not in eku:
        raise CertificateValidationError(f"certificate is not valid for {role} authentication")

    _validate_identity(cert, expected_identity)
    return cert


def verify_private_key_matches_certificate(private_key, cert):
    private_public = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    certificate_public = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if private_public != certificate_public:
        raise CertificateValidationError("private key does not match certificate")


class Session:
    """Bidirectional AEAD session with synchronized, one-way key evolution."""

    def __init__(self, send_key, recv_key, seed_code, role="client"):
        if len(send_key) != 32 or len(recv_key) != 32:
            raise ValueError("session keys must be 32 bytes")
        if len(seed_code) < 32:
            raise ValueError("seed code must contain at least 32 bytes")

        self._send_chain_key = send_key
        self._recv_chain_key = recv_key
        self.seed_code = seed_code
        self.send_seq = 1
        self.recv_seq = 1
        self._send_lock = threading.Lock()
        self._recv_lock = threading.Lock()

        if role == "client":
            self.send_label = b"client->server"
            self.recv_label = b"server->client"
        elif role == "server":
            self.send_label = b"server->client"
            self.recv_label = b"client->server"
        else:
            raise ValueError("invalid session role")

    def _derive_keys(self, chain_key, seq, label):
        context = self.seed_code + struct.pack(">Q", seq) + label
        material = hkdf(chain_key, b"SC-RATCHET|" + context, length=64)
        return material[:32], material[32:]

    def encrypt(self, plaintext: bytes, aad: bytes = b""):
        return self.encrypt_with_sequence(plaintext, aad)[1]

    def encrypt_with_sequence(self, plaintext: bytes, aad: bytes = b""):
        with self._send_lock:
            sequence = self.send_seq
            message_key, next_chain_key = self._derive_keys(
                self._send_chain_key, sequence, self.send_label
            )
            nonce = nonce_from_seq(sequence, self.send_label)
            ciphertext = ChaCha20Poly1305(message_key).encrypt(nonce, plaintext, aad)
            self._send_chain_key = next_chain_key
            self.send_seq += 1
            return sequence, ciphertext

    def decrypt(self, ciphertext: bytes, aad: bytes = b""):
        return self.decrypt_with_sequence(self.recv_seq, ciphertext, aad)

    def decrypt_with_sequence(self, sequence: int, ciphertext: bytes, aad: bytes = b""):
        with self._recv_lock:
            if sequence != self.recv_seq:
                raise SequenceValidationError(
                    f"sequence mismatch: expected {self.recv_seq}, got {sequence}"
                )
            message_key, next_chain_key = self._derive_keys(
                self._recv_chain_key, sequence, self.recv_label
            )
            nonce = nonce_from_seq(sequence, self.recv_label)
            plaintext = ChaCha20Poly1305(message_key).decrypt(nonce, ciphertext, aad)
            self._recv_chain_key = next_chain_key
            self.recv_seq += 1
            return plaintext
