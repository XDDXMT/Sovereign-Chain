"""Issue separate authority, server and client credentials for a new SC deployment."""

import datetime
import ipaddress
import os
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def build_cert(
    subject_name: str,
    issuer_name: str,
    subject_pub,
    issuer_priv,
    is_ca=False,
    path_length=None,
    days_valid=3650,
    san_names=None,
    extended_key_usages=None,
):
    now = datetime.datetime.now(datetime.timezone.utc)

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sovereign Chain"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "SC"),
        ]
    )

    issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sovereign Chain"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "SC"),
        ]
    )

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(subject_pub)
    builder = builder.not_valid_before(now - datetime.timedelta(days=1))
    builder = builder.not_valid_after(now + datetime.timedelta(days=days_valid))
    builder = builder.serial_number(x509.random_serial_number())

    # path_length restricts how many additional issuing CAs may follow this CA.
    builder = builder.add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=path_length), critical=True
    )

    # Only authority keys may sign certificates and revocation lists.
    key_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=is_ca,  # CA证书可以签发其他证书
        crl_sign=is_ca,
        encipher_only=False,
        decipher_only=False,
    )
    builder = builder.add_extension(key_usage, critical=True)

    if san_names:
        names = []
        for name in san_names:
            try:
                names.append(x509.IPAddress(ipaddress.ip_address(name)))
            except ValueError:
                names.append(x509.DNSName(name))
        builder = builder.add_extension(
            x509.SubjectAlternativeName(names), critical=False
        )

    if extended_key_usages:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(extended_key_usages), critical=False
        )

    # 添加主题密钥标识符
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(subject_pub), critical=False
    )

    # 添加颁发者密钥标识符（如果是CA签发的证书）
    if issuer_priv:
        issuer_pub = issuer_priv.public_key()
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_pub),
            critical=False,
        )

    # 签名算法
    if isinstance(issuer_priv, ed25519.Ed25519PrivateKey):
        algorithm = None  # Ed25519不需要指定算法
    elif isinstance(issuer_priv, rsa.RSAPrivateKey):
        algorithm = hashes.SHA256()
    else:
        raise ValueError("Unsupported private key type for signing")

    cert = builder.sign(private_key=issuer_priv, algorithm=algorithm)
    return cert


def _save(directory, stem, key, cert, password):
    protection = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    key_file = directory / (stem + "_key.pem")
    with os.fdopen(
        os.open(key_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb"
    ) as stream:
        stream.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                protection,
            )
        )
    (directory / (stem + "_cert.pem")).write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )


def initialize(destination, ca_password, server_name, client_name):
    """Build in a private staging directory. Publish only a complete, fresh hierarchy."""
    if not ca_password:
        raise ValueError("an authority key password is required")
    if not server_name.strip() or not client_name.strip():
        raise ValueError("both endpoint identities are required")
    destination = Path(destination).expanduser().resolve()
    if destination.exists():
        raise FileExistsError(f"PKI directory already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(
        dir=destination.parent, prefix=".sc-init-"
    ) as staging:
        output = Path(staging) / "pki"
        output.mkdir(mode=0o700)
        authority = output / "authority"
        authority.mkdir(mode=0o700)
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        root = build_cert(
            "Sovereign-Root-CA",
            "Sovereign-Root-CA",
            root_key.public_key(),
            root_key,
            is_ca=True,
            path_length=1,
        )
        _save(authority, "root_ca", root_key, root, ca_password)
        issuer_key = ed25519.Ed25519PrivateKey.generate()
        issuer = build_cert(
            "Sovereign-Intermediate-CA",
            "Sovereign-Root-CA",
            issuer_key.public_key(),
            root_key,
            is_ca=True,
            path_length=0,
            days_valid=1825,
        )
        _save(authority, "intermediate_ca", issuer_key, issuer, ca_password)
        for role, identity, usage in (
            ("server", server_name, ExtendedKeyUsageOID.SERVER_AUTH),
            ("client", client_name, ExtendedKeyUsageOID.CLIENT_AUTH),
        ):
            folder = output / role
            folder.mkdir(mode=0o700)
            key = ed25519.Ed25519PrivateKey.generate()
            cert = build_cert(
                identity,
                "Sovereign-Intermediate-CA",
                key.public_key(),
                issuer_key,
                days_valid=365,
                san_names=[identity],
                extended_key_usages=[usage],
            )
            password = os.getenv(f"SC_{role.upper()}_KEY_PASSWORD")
            _save(folder, role, key, cert, password.encode() if password else None)
            (folder / "ca_cert.pem").write_bytes(
                issuer.public_bytes(serialization.Encoding.PEM)
            )
        output.rename(destination)
    return destination
