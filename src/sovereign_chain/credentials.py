"""Per-role credential lookup. The application only loads the endpoint's own key."""

import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .security import validate_peer_certificate, verify_private_key_matches_certificate

SERVER_NAME = "Sovereign-Chain-Server"
CLIENT_NAME = "Sovereign-Chain-Client"


def pki_directory():
    return Path(
        os.getenv("SC_PKI_DIR") or Path.home() / ".sovereign-chain" / "pki"
    ).expanduser()


def role_file(role, variable, filename):
    path = os.getenv(variable)
    return Path(path).expanduser() if path else pki_directory() / role / filename


def load_certificate(role, ca=False):
    if ca:
        path = role_file(role, "SC_CA_CERT_FILE", "ca_cert.pem")
    else:
        path = role_file(role, f"SC_{role.upper()}_CERT_FILE", f"{role}_cert.pem")
    return x509.load_pem_x509_certificate(path.read_bytes())


def load_key(role):
    path = role_file(role, f"SC_{role.upper()}_KEY_FILE", f"{role}_key.pem")
    password = os.getenv(f"SC_{role.upper()}_KEY_PASSWORD")
    key = serialization.load_pem_private_key(
        path.read_bytes(), password.encode() if password else None
    )
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("SC-EE-3 requires Ed25519 endpoint keys")
    return key


def server_credentials():
    key = load_key("server")
    cert = load_certificate("server")
    anchor = load_certificate("server", ca=True)
    validate_peer_certificate(
        cert, anchor, "server", os.getenv("SC_SERVER_NAME", SERVER_NAME)
    )
    verify_private_key_matches_certificate(key, cert)
    return key, cert, anchor
