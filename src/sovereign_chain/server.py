"""Authenticate a named client and establish a SC-EE-3 session."""

import os

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from .credentials import CLIENT_NAME
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
)
from .trust import FROM_ENV, require_identity
from .wire import HandshakeIO, payload
from .wire import ProtocolError as ProtocolError

CLIENT_HELLO_PREFIX = b"CLIENTHELLO|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|"
SERVER_HELLO_PREFIX = b"SERVERHELLO|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|"
client_nonces = ReplayWindow()


def authorized_certificate(pem, anchor, names=None, revocations=FROM_ENV):
    cert = x509.load_pem_x509_certificate(pem)
    validate_peer_certificate(cert, anchor, "client", revocations=revocations)
    allowed = (
        os.getenv("SC_ALLOWED_CLIENT_NAMES", CLIENT_NAME).split(",")
        if names is None
        else names
    )
    require_identity(cert, allowed)
    return cert


def server_handshake(
    conn,
    addr,
    server_priv,
    server_cert,
    ca_cert,
    *,
    allowed_names=None,
    revocations=FROM_ENV,
):
    """The caller owns conn on both success and failure."""
    stream = HandshakeIO(conn)
    hello = payload(stream.receive(), CLIENT_HELLO_PREFIX, 48)
    client_nonce = hello[32:]
    client_nonces.remember(client_nonce)
    ephemeral = x25519.X25519PrivateKey.generate()
    server_nonce = os.urandom(16)
    stream.send(
        SERVER_HELLO_PREFIX + ephemeral.public_key().public_bytes_raw() + server_nonce,
        b"SERVERCERTSEND|" + server_cert.public_bytes(serialization.Encoding.PEM),
        b"CLIENTCERTREQUEST|",
    )
    shared = ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(hello[:32]))
    client_cert = authorized_certificate(
        payload(stream.receive(), b"CLIENTCERTSEND|"),
        ca_cert,
        allowed_names,
        revocations,
    )
    context = key_context(CIPHER_SUITE, client_nonce, server_nonce)
    prior = stream.digest.digest()
    seed = os.urandom(64)
    temporary = create_aead(hkdf(shared, context, length=64)[32:], CIPHER_SUITE)
    seed_message = temporary.encrypt(
        prior[:12], b"SEEDCODE|" + os.urandom(8) + seed + os.urandom(32), prior
    )
    fields = [os.urandom(32) for _ in KEY_FIELDS]
    stream.send(
        seed_message, *(name + value for name, value in zip(KEY_FIELDS, fields))
    )

    prior = stream.digest.digest()
    signature = payload(stream.receive(), b"CLIENTAUTH|", 64)
    verify_peer_signature(client_cert, signature, prior)
    stream.send(b"SERVERAUTH|" + server_priv.sign(stream.digest.digest()))
    # Both peers bind the first ACK and every later record to this transcript.
    transcript = stream.digest.digest()
    session = make_session(
        "server", CIPHER_SUITE, shared, context, fields, seed, transcript
    )
    ack = session.encrypt(b"ACK", aad=transcript, frame_type=b"SECUREACK")
    stream.send(b"SECUREACK|" + ack)
    session.peer_expires = client_cert.not_valid_after_utc
    conn.settimeout(None)
    return session
