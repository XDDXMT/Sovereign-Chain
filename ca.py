#!/usr/bin/env python3
# ca.py
"""
证书签发程序（示例 CA）。
用法：
  python ca.py
会生成：
  - ca_key.pem, ca_cert.pem
  - server_key.pem, server_cert.pem
  - client_key.pem, client_cert.pem
"""
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

def save_pem(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)
    print("wrote", path)

def gen_ed25519_key():
    return ed25519.Ed25519PrivateKey.generate()


def build_cert(subject_name: str, issuer_name: str, subject_pub, issuer_priv, is_ca=False, days_valid=3650):
    import datetime, pytz  # 可选：使时间对象 timezone aware
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])
    now = datetime.datetime.now(datetime.timezone.utc)  # 避免 utcnow() 的 DeprecationWarning
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(subject_pub)
    builder = builder.not_valid_before(now - datetime.timedelta(days=1))
    builder = builder.not_valid_after(now + datetime.timedelta(days=days_valid))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)

    # Ed25519 不需要算法参数，直接传 None
    cert = builder.sign(private_key=issuer_priv, algorithm=None)
    return cert


def main():
    # 1) 生成 CA (Ed25519)
    ca_priv = gen_ed25519_key()
    ca_pub = ca_priv.public_key()
    ca_cert = build_cert("Sovereign-Chain-CA", "Sovereign-Chain-CA", ca_pub, ca_priv, is_ca=True, days_valid=3650)
    save_pem("ca_key.pem", ca_priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    save_pem("ca_cert.pem", ca_cert.public_bytes(Encoding.PEM))

    # 2) 生成 Server 静态签名密钥和证书
    server_priv = gen_ed25519_key()
    server_pub = server_priv.public_key()
    server_cert = build_cert("Sovereign-Chain-Server", "Sovereign-Chain-CA", server_pub, ca_priv, is_ca=False, days_valid=3650)
    save_pem("server_key.pem", server_priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    save_pem("server_cert.pem", server_cert.public_bytes(Encoding.PEM))

    # 3) 生成 Client 静态签名密钥和证书
    client_priv = gen_ed25519_key()
    client_pub = client_priv.public_key()
    client_cert = build_cert("Sovereign-Chain-Client", "Sovereign-Chain-CA", client_pub, ca_priv, is_ca=False, days_valid=3650)
    save_pem("client_key.pem", client_priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    save_pem("client_cert.pem", client_cert.public_bytes(Encoding.PEM))

    print("CA and certs generated: ca_cert.pem, ca_key.pem, server_cert.pem, server_key.pem, client_cert.pem, client_key.pem")

if __name__ == "__main__":
    main()
