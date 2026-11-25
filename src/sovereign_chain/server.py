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
from .wire import HandshakeIO, ProtocolError, payload

CLIENT_HELLO_PREFIX = b"CLIENTHELLO|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|"
SERVER_HELLO_PREFIX = b"SERVERHELLO|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|"
client_nonces = ReplayWindow()


def authorized_certificate(pem, anchor):
    cert = x509.load_pem_x509_certificate(pem)
    validate_peer_certificate(cert, anchor, "client")
    allowed = {
        name.strip().casefold()
        for name in os.getenv("SC_ALLOWED_CLIENT_NAMES", CLIENT_NAME).split(",")
        if name.strip()
    }
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    names = {name.casefold() for name in san.get_values_for_type(x509.DNSName)}
    names.update(str(ip) for ip in san.get_values_for_type(x509.IPAddress))
    if not allowed.intersection(names):
        raise ProtocolError("client identity is not authorized")
    return cert


def server_handshake(conn, addr, server_priv, server_cert, ca_cert):
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
        payload(stream.receive(), b"CLIENTCERTSEND|"), ca_cert
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
    conn.settimeout(None)
    return session
