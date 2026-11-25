"""Shared security primitives for the Sovereign-Chain protocol."""

import hashlib
import hmac
import os
import secrets
import struct
import threading
from functools import lru_cache

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# The original public imports remain available to applications.
from .trust import CertificateValidationError as CertificateValidationError
from .trust import check_certificate_revocation as check_certificate_revocation
from .trust import validate_ca_certificate as validate_ca_certificate
from .trust import validate_peer_certificate as validate_peer_certificate
from .trust import verify_certificate_signature as verify_certificate_signature
from .trust import (
    verify_private_key_matches_certificate as verify_private_key_matches_certificate,
)

PROTO_VER = b"SC-EE-3"
CHACHA20_SUITE = b"X25519-Ed25519-CHACHA20POLY1305-HKDFSHA256"
AES256_GCM_SIV_SUITE = b"X25519-Ed25519-AES256GCMSIV-HKDFSHA256"
_CIPHER_ALIASES = {
    "CHACHA20-POLY1305": CHACHA20_SUITE,
    "CHACHA20": CHACHA20_SUITE,
    "AES-256-GCM-SIV": AES256_GCM_SIV_SUITE,
    "AES256-GCM-SIV": AES256_GCM_SIV_SUITE,
}
_configured_cipher = os.getenv("SC_CIPHER_SUITE", "CHACHA20-POLY1305").strip().upper()
if _configured_cipher not in _CIPHER_ALIASES:
    raise RuntimeError(f"unsupported SC_CIPHER_SUITE: {_configured_cipher}")
CIPHER_SUITE = _CIPHER_ALIASES[_configured_cipher]
MAX_FRAME_SIZE = 1_000_000
RECORD_HEADER_SIZE = 12  # Four-byte type and eight-byte sequence are inside the frame.
PADDING_MAGIC = b"P1"
PADDING_HEADER = struct.Struct(">2sHI")
MAX_ACCEPTED_PADDING = 256
DEFAULT_MIN_PADDING = 0
DEFAULT_MAX_PADDING = 32


class SequenceValidationError(ValueError):
    pass


class PaddingValidationError(ValueError):
    pass


def create_aead(key, cipher_suite=None):
    selected_suite = CIPHER_SUITE if cipher_suite is None else cipher_suite
    if selected_suite == CHACHA20_SUITE:
        return ChaCha20Poly1305(key)
    if selected_suite != AES256_GCM_SIV_SUITE:
        raise ValueError("unsupported AEAD cipher suite")
    return AESGCMSIV(key)


def hkdf(ikm, info, length=64):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(ikm)


@lru_cache(maxsize=4)
def _nonce_prefix(label):
    # The two constant direction labels dominate this call on both endpoints.
    return hashlib.sha256(label).digest()[:4]


def nonce_from_seq(seq: int, label: bytes):
    return _nonce_prefix(label) + struct.pack(">Q", seq)


class Session:
    """Bidirectional AEAD session with key evolution and authenticated padding."""

    def __init__(
        self,
        send_key,
        recv_key,
        seed_code,
        role="client",
        session_id=None,
        cipher_suite=None,
        epoch=0,
    ):
        if len(send_key) != 32 or len(recv_key) != 32:
            raise ValueError("session keys must be 32 bytes")
        if len(seed_code) < 32:
            raise ValueError("seed code must contain at least 32 bytes")

        self._send_chain_key = send_key
        self._recv_chain_key = recv_key
        self.seed_code = seed_code
        self.session_id = (
            hkdf(seed_code, b"SC-SESSION-ID", length=32)
            if session_id is None
            else session_id
        )
        if not isinstance(self.session_id, bytes) or len(self.session_id) != 32:
            raise ValueError("session ID must be 32 bytes")
        self.cipher_suite = CIPHER_SUITE if cipher_suite is None else cipher_suite
        if self.cipher_suite not in {CHACHA20_SUITE, AES256_GCM_SIV_SUITE}:
            raise ValueError("unsupported session cipher suite")
        if not isinstance(epoch, int) or epoch < 0 or epoch > 0xFFFFFFFF:
            raise ValueError("invalid key epoch")
        self.epoch = epoch
        self.send_seq = 1
        self.recv_seq = 1
        self._send_lock = threading.Lock()
        self._recv_lock = threading.Lock()
        self._min_padding, self._max_padding = self._read_padding_bounds()

        if role == "client":
            self.send_label = b"client->server"
            self.recv_label = b"server->client"
        elif role == "server":
            self.send_label = b"server->client"
            self.recv_label = b"client->server"
        else:
            raise ValueError("invalid session role")

    def _derive_keys(self, chain_key, seq, label):
        # Separate message key, next chain key and padding material with one HKDF expansion.
        context = self.seed_code + struct.pack(">Q", seq) + label
        material = hkdf(chain_key, b"SC-RATCHET|" + context, length=96)
        return material[:32], material[32:64], material[64:96]

    def _build_aad(self, sequence, label, frame_type, external_aad):
        # Authenticate the record type and direction before advancing the receive chain.
        if not isinstance(frame_type, bytes) or not frame_type:
            raise ValueError("frame type must be non-empty bytes")
        if len(frame_type) > 255:
            raise ValueError("frame type is too long")
        if not isinstance(external_aad, bytes):
            raise TypeError("AAD must be bytes")
        return (
            b"SC-AAD1"
            + bytes([len(PROTO_VER)])
            + PROTO_VER
            + bytes([len(self.cipher_suite)])
            + self.cipher_suite
            + self.session_id
            + struct.pack(">I", self.epoch)
            + bytes([len(label)])
            + label
            + bytes([len(frame_type)])
            + frame_type
            + struct.pack(">Q", sequence)
            + struct.pack(">I", len(external_aad))
            + external_aad
        )

    def _new_aead(self, key):
        return create_aead(key, self.cipher_suite)

    @staticmethod
    def _read_padding_bounds():
        try:
            minimum = int(os.getenv("SC_MIN_PADDING_BYTES", str(DEFAULT_MIN_PADDING)))
            maximum = int(os.getenv("SC_MAX_PADDING_BYTES", str(DEFAULT_MAX_PADDING)))
        except ValueError as exc:
            raise ValueError("padding limits must be integers") from exc
        if minimum < 0 or maximum > MAX_ACCEPTED_PADDING or minimum > maximum:
            raise ValueError(
                f"padding limits must satisfy 0 <= minimum <= maximum <= "
                f"{MAX_ACCEPTED_PADDING}"
            )
        return minimum, maximum

    def _derive_padding(
        self,
        padding_material,
        padding_length,
        insertion_position,
    ):
        if padding_length == 0:
            return b""
        if padding_length <= len(padding_material):
            return padding_material[:padding_length]
        context = b"SC-PADDING-EXPAND|" + struct.pack(">I", insertion_position)
        return hkdf(padding_material, context, length=padding_length)

    def _encode_padded(self, plaintext, padding_material):
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        padding_length = self._min_padding + secrets.randbelow(
            self._max_padding - self._min_padding + 1
        )
        insertion_position = secrets.randbelow(len(plaintext) + 1)
        padding = self._derive_padding(
            padding_material, padding_length, insertion_position
        )
        envelope_length = PADDING_HEADER.size + len(plaintext) + padding_length
        if RECORD_HEADER_SIZE + envelope_length + 16 > MAX_FRAME_SIZE:
            raise ValueError("padded plaintext exceeds maximum frame size")
        header = PADDING_HEADER.pack(
            PADDING_MAGIC,
            padding_length,
            insertion_position,
        )
        data = memoryview(plaintext)
        return b"".join(
            (header, data[:insertion_position], padding, data[insertion_position:])
        )

    def _decode_padded(self, envelope, padding_material):
        if len(envelope) < PADDING_HEADER.size:
            raise PaddingValidationError("padding envelope is truncated")
        magic, padding_length, insertion_position = PADDING_HEADER.unpack_from(envelope)
        if magic != PADDING_MAGIC:
            raise PaddingValidationError("invalid padding envelope")
        if padding_length > MAX_ACCEPTED_PADDING:
            raise PaddingValidationError("padding length exceeds protocol limit")
        original_length = len(envelope) - PADDING_HEADER.size - padding_length
        if original_length < 0 or insertion_position > original_length:
            raise PaddingValidationError("invalid padding insertion position or length")

        padded_data = memoryview(envelope)[PADDING_HEADER.size :]
        padding_end = insertion_position + padding_length
        supplied_padding = padded_data[insertion_position:padding_end]
        expected_padding = self._derive_padding(
            padding_material, padding_length, insertion_position
        )
        if not hmac.compare_digest(supplied_padding, expected_padding):
            raise PaddingValidationError("seed-bound padding verification failed")
        plaintext = b"".join(
            (padded_data[:insertion_position], padded_data[padding_end:])
        )
        if len(plaintext) != original_length:
            raise PaddingValidationError("decoded plaintext length mismatch")
        return plaintext

    def encrypt(self, plaintext: bytes, aad: bytes = b"", frame_type: bytes = b"DATA"):
        return self.encrypt_with_sequence(plaintext, aad, frame_type)[1]

    def encrypt_with_sequence(
        self,
        plaintext: bytes,
        aad: bytes = b"",
        frame_type: bytes = b"DATA",
    ):
        with self._send_lock:
            sequence = self.send_seq
            message_key, next_chain_key, padding_material = self._derive_keys(
                self._send_chain_key, sequence, self.send_label
            )
            nonce = nonce_from_seq(sequence, self.send_label)
            padded_plaintext = self._encode_padded(plaintext, padding_material)
            authenticated_data = self._build_aad(
                sequence, self.send_label, frame_type, aad
            )
            ciphertext = self._new_aead(message_key).encrypt(
                nonce, padded_plaintext, authenticated_data
            )
            self._send_chain_key = next_chain_key
            self.send_seq += 1
            return sequence, ciphertext

    def decrypt(self, ciphertext: bytes, aad: bytes = b"", frame_type: bytes = b"DATA"):
        return self.decrypt_with_sequence(self.recv_seq, ciphertext, aad, frame_type)

    def decrypt_with_sequence(
        self,
        sequence: int,
        ciphertext: bytes,
        aad: bytes = b"",
        frame_type: bytes = b"DATA",
    ):
        with self._recv_lock:
            if sequence != self.recv_seq:
                raise SequenceValidationError(
                    f"sequence mismatch: expected {self.recv_seq}, got {sequence}"
                )
            message_key, next_chain_key, padding_material = self._derive_keys(
                self._recv_chain_key, sequence, self.recv_label
            )
            nonce = nonce_from_seq(sequence, self.recv_label)
            authenticated_data = self._build_aad(
                sequence, self.recv_label, frame_type, aad
            )
            padded_plaintext = self._new_aead(message_key).decrypt(
                nonce, ciphertext, authenticated_data
            )
            plaintext = self._decode_padded(padded_plaintext, padding_material)
            self._recv_chain_key = next_chain_key
            self.recv_seq += 1
            return plaintext
