"""Authenticated SC-EE-3 client handshake."""

import os
import socket

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from .credentials import SERVER_NAME, load_certificate, load_key
from .handshake import (
    KEY_FIELDS,
    ReplayWindow,
    key_context,
    make_session,
    verify_peer_signature,
)
from .security import (
    CIPHER_SUITE,
    PROTO_VER,
    create_aead,
    hkdf,
    validate_peer_certificate,
    verify_private_key_matches_certificate,
)
from .trust import FROM_ENV
from .wire import HANDSHAKE_TIMEOUT, HandshakeIO, ProtocolError, payload

CLIENT_HELLO_PREFIX = b"CLIENTHELLO|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|"
SERVER_HELLO_PREFIX = b"SERVERHELLO|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|"
seed_nonces = ReplayWindow()


def load_client_credentials():
    key = load_key("client")
    cert = load_certificate("client")
    verify_private_key_matches_certificate(key, cert)
    return key, cert, load_certificate("client", ca=True)


def client_handshake(
    host="127.0.0.1", port=5555, expected_server_name=None, *, identity=None
):
    """Return the authenticated session and its connected socket to the caller."""
    sock = socket.create_connection((host, port), timeout=HANDSHAKE_TIMEOUT)
    try:
        session = authenticate_client(sock, expected_server_name, identity)
        return session, sock
    except BaseException:
        sock.close()
        raise


def authenticate_client(sock, expected_server_name=None, identity=None):
    """Authenticate a socket owned by the listener, so rotations can interrupt it."""
    if identity is None:
        key, cert, anchor = load_client_credentials()
        revocations = FROM_ENV
    else:
        key, cert, anchor = identity.key, identity.cert, identity.anchor
        revocations = identity.revocations
    expected = expected_server_name or os.getenv("SC_SERVER_NAME", SERVER_NAME)
    if not expected.strip():
        raise ValueError("an expected server identity is required")
    stream = HandshakeIO(sock)
    ephemeral = x25519.X25519PrivateKey.generate()
    client_nonce = os.urandom(16)
    stream.send(
        CLIENT_HELLO_PREFIX + ephemeral.public_key().public_bytes_raw() + client_nonce
    )

    hello = payload(stream.receive(), SERVER_HELLO_PREFIX, 48)
    shared = ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(hello[:32]))
    context = key_context(CIPHER_SUITE, client_nonce, hello[32:])
    server_cert = x509.load_pem_x509_certificate(
        payload(stream.receive(), b"SERVERCERTSEND|")
    )
    validate_peer_certificate(
        server_cert, anchor, "server", expected, revocations=revocations
    )
    payload(stream.receive(), b"CLIENTCERTREQUEST|", 0)
    stream.send(b"CLIENTCERTSEND|" + cert.public_bytes(serialization.Encoding.PEM))

    # The seed record authenticates the transcript through ClientCertSend.
    prior = stream.digest.digest()
    temporary = create_aead(hkdf(shared, context, length=64)[32:], CIPHER_SUITE)
    seed_frame = temporary.decrypt(prior[:12], stream.receive(), prior)
    # Legacy SC-EE-3 reserves the final 32 bytes; its 64-byte seed starts at byte 8.
    seed_data = payload(seed_frame, b"SEEDCODE|", 104)
    fields = [payload(stream.receive(), name, 32) for name in KEY_FIELDS]

    stream.send(b"CLIENTAUTH|" + key.sign(stream.digest.digest()))
    prior = stream.digest.digest()
    signature = payload(stream.receive(), b"SERVERAUTH|", 64)
    verify_peer_signature(server_cert, signature, prior)
    transcript = stream.digest.digest()
    session = make_session(
        "client", CIPHER_SUITE, shared, context, fields, seed_data[8:72], transcript
    )

    ack = payload(stream.receive(), b"SECUREACK|")
    if session.decrypt(ack, aad=transcript, frame_type=b"SECUREACK") != b"ACK":
        raise ProtocolError("invalid key confirmation")
    seed_nonces.remember(seed_data[:8])
    session.peer_expires = server_cert.not_valid_after_utc
    sock.settimeout(None)
    return session
