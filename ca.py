#!/usr/bin/env python3
# ca.py
"""
证书签发程序（支持根证书、中级CA签发和匿名证书）
用法：
  python ca.py
会生成：
  - root_ca_key.pem, root_ca_cert.pem (根证书)
  - intermediate_ca_key.pem, intermediate_ca_cert.pem (中级CA)
  - server_key.pem, server_cert.pem
  - client_key.pem, client_cert.pem (可选)
  - anonymous_ca_key.pem, anonymous_ca_cert.pem (匿名证书)
  - ca_cert.pem (服务端和客户端使用的CA证书)
"""
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib
import os
import shutil


def save_pem(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)
    print("wrote", path)


def gen_ed25519_key():
    return ed25519.Ed25519PrivateKey.generate()


def gen_rsa_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


def build_cert(subject_name: str, issuer_name: str, subject_pub, issuer_priv,
               is_ca=False, path_length=None, days_valid=3650):
    now = datetime.datetime.now(datetime.timezone.utc)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sovereign Chain"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "SC")
    ])

    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sovereign Chain"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "SC")
    ])

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(subject_pub)
    builder = builder.not_valid_before(now - datetime.timedelta(days=1))
    builder = builder.not_valid_after(now + datetime.timedelta(days=days_valid))
    builder = builder.serial_number(x509.random_serial_number())

    # 添加基本约束扩展
    builder = builder.add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=path_length),
        critical=True
    )

    # 添加密钥用途扩展
    key_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=is_ca,  # CA证书可以签发其他证书
        crl_sign=is_ca,
        encipher_only=False,
        decipher_only=False
    )
    builder = builder.add_extension(key_usage, critical=True)

    # 添加主题密钥标识符
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(subject_pub),
        critical=False
    )

    # 添加颁发者密钥标识符（如果是CA签发的证书）
    if issuer_priv:
        issuer_pub = issuer_priv.public_key()
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_pub),
            critical=False
        )

    # 签名算法
    if isinstance(issuer_priv, ed25519.Ed25519PrivateKey):
        algorithm = None  # Ed25519不需要指定算法
    elif isinstance(issuer_priv, rsa.RSAPrivateKey):  # 修复拼写错误
        algorithm = hashes.SHA256()
    else:
        raise ValueError("Unsupported private key type for signing")

    cert = builder.sign(private_key=issuer_priv, algorithm=algorithm)
    return cert


def cert_fingerprint(cert):
    der = cert.public_bytes(Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def main():
    # 1) 生成根CA (RSA 2048)
    print("Generating Root CA...")
    root_ca_priv = gen_rsa_key()
    root_ca_pub = root_ca_priv.public_key()
    root_ca_cert = build_cert(
        "Sovereign-Root-CA",
        "Sovereign-Root-CA",
        root_ca_pub,
        root_ca_priv,
        is_ca=True,
        path_length=1,  # 允许一级中级CA
        days_valid=3650
    )
    save_pem("root_ca_key.pem", root_ca_priv.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption()
    ))
    save_pem("root_ca_cert.pem", root_ca_cert.public_bytes(Encoding.PEM))

    # 2) 生成中级CA (Ed25519)
    print("Generating Intermediate CA...")
    intermediate_ca_priv = gen_ed25519_key()
    intermediate_ca_pub = intermediate_ca_priv.public_key()
    intermediate_ca_cert = build_cert(
        "Sovereign-Intermediate-CA",
        "Sovereign-Root-CA",
        intermediate_ca_pub,
        root_ca_priv,
        is_ca=True,
        path_length=0,  # 不允许再签发下级CA
        days_valid=1825
    )
    save_pem("intermediate_ca_key.pem", intermediate_ca_priv.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption()
    ))
    save_pem("intermediate_ca_cert.pem", intermediate_ca_cert.public_bytes(Encoding.PEM))

    # 创建服务端和客户端使用的CA证书文件
    shutil.copyfile("intermediate_ca_cert.pem", "ca_cert.pem")
    print("Created ca_cert.pem from intermediate_ca_cert.pem")

    # 3) 生成 Server 证书
    print("Generating Server Certificate...")
    server_priv = gen_ed25519_key()
    server_pub = server_priv.public_key()
    server_cert = build_cert(
        "Sovereign-Chain-Server",
        "Sovereign-Intermediate-CA",
        server_pub,
        intermediate_ca_priv,
        is_ca=False,
        days_valid=365
    )
    save_pem("server_key.pem", server_priv.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption()
    ))
    save_pem("server_cert.pem", server_cert.public_bytes(Encoding.PEM))

    # 4) 生成 Client 证书（可选）
    print("Generating Client Certificate...")
    client_priv = gen_ed25519_key()
    client_pub = client_priv.public_key()
    client_cert = build_cert(
        "Sovereign-Chain-Client",
        "Sovereign-Intermediate-CA",
        client_pub,
        intermediate_ca_priv,
        is_ca=False,
        days_valid=365
    )
    save_pem("client_key.pem", client_priv.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption()
    ))
    save_pem("client_cert.pem", client_cert.public_bytes(Encoding.PEM))

    # 5) 生成匿名CA证书（用于签发临时证书）
    print("Generating Anonymous CA Certificate...")
    anonymous_ca_priv = gen_ed25519_key()
    anonymous_ca_pub = anonymous_ca_priv.public_key()
    anonymous_ca_cert = build_cert(
        "Sovereign-Anonymous-CA",
        "Sovereign-Intermediate-CA",
        anonymous_ca_pub,
        intermediate_ca_priv,
        is_ca=True,
        path_length=0,
        days_valid=365
    )
    save_pem("anonymous_ca_key.pem", anonymous_ca_priv.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption()
    ))
    save_pem("anonymous_ca_cert.pem", anonymous_ca_cert.public_bytes(Encoding.PEM))

    # 输出证书指纹
    print("\nCertificate Fingerprints:")
    print(f"Root CA: {cert_fingerprint(root_ca_cert)}")
    print(f"Intermediate CA: {cert_fingerprint(intermediate_ca_cert)}")
    print(f"Server: {cert_fingerprint(server_cert)}")
    print(f"Client: {cert_fingerprint(client_cert)}")
    print(f"Anonymous CA: {cert_fingerprint(anonymous_ca_cert)}")

    print("\nCA and certs generated:")
    print("root_ca_key.pem, root_ca_cert.pem")
    print("intermediate_ca_key.pem, intermediate_ca_cert.pem")
    print("server_cert.pem, server_key.pem")
    print("client_cert.pem, client_key.pem (optional)")
    print("anonymous_ca_key.pem, anonymous_ca_cert.pem")
    print("ca_cert.pem (for server and client)")


if __name__ == "__main__":
    main()