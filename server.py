#!/usr/bin/env python3
# server.py
"""
Sovereign-Chain Server - 12次超级无敌宇宙加密握手版本
握手步骤（严格按顺序，12 步）：
1) ClientHello      : client_eph_pub || nonce_c
2) ServerHello      : server_eph_pub || nonce_s
3) ServerCertSend   : server_cert (PEM)
4) ClientCertRequest: "REQUEST_CLIENT_CERT"
5) ClientCertSend   : client_cert (PEM)
6) KeyExchange1     : 额外的密钥交换数据1
7) KeyExchange2     : 额外的密钥交换数据2
8) KeyConfirm1      : 密钥确认数据1
9) KeyConfirm2      : 密钥确认数据2
10) ClientAuth      : signature_client(transcript_so_far)
11) ServerAuth      : signature_server(transcript_so_far)
12) SecureAck       : encrypted ACK using derived keys (proves key confirmation)

随后所有 DATA 帧都用 AEAD (ChaCha20-Poly1305) 发送（带序号防重放）。
"""

import socket, struct, os, threading
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography import x509

FRAME_HDR = 4
PROTO_VER = b"SC-EE-1"
CIPHER_SUITE = b"X25519-Ed25519-CHACHA20POLY1305-HKDFSHA256"


def pack(buf: bytes) -> bytes:
    return struct.pack(">I", len(buf)) + buf


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        r = sock.recv(n - len(buf))
        if not r:
            raise ConnectionError("peer closed")
        buf += r
    return buf


def recv_frame(sock):
    hdr = recv_exact(sock, FRAME_HDR)
    (l,) = struct.unpack(">I", hdr)
    if l > 50_000_000: raise ValueError("too large")
    return recv_exact(sock, l)


def load_pem_priv(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_pem_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def hkdf(ikm, info, length=64):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(ikm)


def nonce_from_seq(seq: int, label: bytes):
    h = hashes.Hash(hashes.SHA256());
    h.update(label);
    prefix = h.finalize()[:4]
    return prefix + struct.pack(">Q", seq)


class Session:
    def __init__(self, send_key, recv_key):
        self.send_aead = ChaCha20Poly1305(send_key)
        self.recv_aead = ChaCha20Poly1305(recv_key)
        self.send_seq = 0
        self.recv_seq = 0
        self.send_label = b"server->client"
        self.recv_label = b"client->server"

    def encrypt(self, pt: bytes, aad: bytes = b""):
        n = nonce_from_seq(self.send_seq, self.send_label);
        self.send_seq += 1
        return self.send_aead.encrypt(n, pt, aad)

    def decrypt(self, ct: bytes, aad: bytes = b""):
        n = nonce_from_seq(self.recv_seq, self.recv_label);
        pt = self.recv_aead.decrypt(n, ct, aad);
        self.recv_seq += 1
        return pt


def handle_conn(conn, addr, server_priv, server_cert, ca_cert):
    print("conn from", addr)
    try:
        # 1) ClientHello
        ch = recv_frame(conn)
        if not ch.startswith(b"CLIENTHELLO|"):
            raise ValueError("expected CLIENTHELLO")
        payload = ch.split(b"|", 1)[1]
        client_eph_pub = payload[:32];
        nonce_c = payload[32:48]
        transcript = ch

        # 2) ServerHello
        server_eph = x25519.X25519PrivateKey.generate()
        server_eph_pub = server_eph.public_key().public_bytes(serialization.Encoding.Raw,
                                                              serialization.PublicFormat.Raw)
        nonce_s = os.urandom(16)
        sh = b"SERVERHELLO|" + server_eph_pub + nonce_s
        conn.sendall(pack(sh))
        transcript += sh

        # 3) ServerCertSend
        scert = b"SERVERCERTSEND|" + server_cert.public_bytes(serialization.Encoding.PEM)
        conn.sendall(pack(scert))
        transcript += scert

        # 4) ClientCertRequest
        ccr = b"CLIENTCERTREQUEST|"
        conn.sendall(pack(ccr))
        transcript += ccr

        # 5) ClientCertSend
        ccert_frame = recv_frame(conn)
        if not ccert_frame.startswith(b"CLIENTCERTSEND|"):
            raise ValueError("expected CLIENTCERTSEND")
        client_cert_pem = ccert_frame.split(b"|", 1)[1]
        client_cert = x509.load_pem_x509_certificate(client_cert_pem)
        transcript += ccert_frame

        # 验证客户端证书
        ca_pub = ca_cert.public_key()
        try:
            ca_pub.verify(client_cert.signature, client_cert.tbs_certificate_bytes)
        except Exception as e:
            raise ValueError("client cert verify failed: " + str(e))

        # 6) KeyExchange1 - 额外的密钥交换数据
        ke1_data = os.urandom(32)
        ke1 = b"KEYEXCHANGE1|" + ke1_data
        conn.sendall(pack(ke1))
        transcript += ke1

        # 7) KeyExchange2 - 额外的密钥交换数据
        ke2_frame = recv_frame(conn)
        if not ke2_frame.startswith(b"KEYEXCHANGE2|"):
            raise ValueError("expected KEYEXCHANGE2")
        ke2_data = ke2_frame.split(b"|", 1)[1]
        transcript += ke2_frame

        # 8) KeyConfirm1 - 密钥确认
        kc1_data = os.urandom(32)
        kc1 = b"KEYCONFIRM1|" + kc1_data
        conn.sendall(pack(kc1))
        transcript += kc1

        # 9) KeyConfirm2 - 密钥确认
        kc2_frame = recv_frame(conn)
        if not kc2_frame.startswith(b"KEYCONFIRM2|"):
            raise ValueError("expected KEYCONFIRM2")
        kc2_data = kc2_frame.split(b"|", 1)[1]
        transcript += kc2_frame

        # 计算共享密钥（包含额外的密钥交换数据）
        shared = server_eph.exchange(x25519.X25519PublicKey.from_public_bytes(client_eph_pub))
        # 将额外的密钥交换数据加入密钥派生
        extra_key_material = ke1_data + ke2_data + kc1_data + kc2_data
        info = b"SC-HKDF" + PROTO_VER + CIPHER_SUITE + nonce_c + nonce_s + extra_key_material
        okm = hkdf(shared, info, length=64)
        k_c2s = okm[:32];
        k_s2c = okm[32:]

        # 10) ClientAuth: client signature over transcript
        caut = recv_frame(conn)
        if not caut.startswith(b"CLIENTAUTH|"):
            raise ValueError("expected CLIENTAUTH")
        sig_client = caut.split(b"|", 1)[1]
        # verify client's signature using public key in certificate
        client_pub = client_cert.public_key()
        client_pub.verify(sig_client, transcript)
        transcript += caut

        # 11) ServerAuth: server signs transcript and sends
        sig_server = server_priv.sign(transcript)
        sa = b"SERVERAUTH|" + sig_server
        conn.sendall(pack(sa))
        transcript += sa

        # 12) SecureAck: encrypted "ACK"
        sess = Session(send_key=k_s2c, recv_key=k_c2s)
        ct = sess.encrypt(b"ACK", aad=transcript)
        conn.sendall(pack(b"SECUREACK|" + ct))

        print("[server] 12次握手完成 with", addr)
        # 后续加密通信（示例 echo）
        while True:
            frm = recv_frame(conn)
            if not frm.startswith(b"DATA|"):
                print("bad frame:", frm[:50])
                break
            ct = frm.split(b"|", 1)[1]
            try:
                pt = sess.decrypt(ct)
            except Exception as e:
                print("decrypt err", e);
                break
            print("[server] got:", pt)
            # 回显
            resp = b"echo: " + pt
            conn.sendall(pack(b"DATA|" + sess.encrypt(resp)))
    except Exception as e:
        print("connection error:", e)
    finally:
        conn.close()


def main():
    server_priv = load_pem_priv("server_key.pem")
    server_cert = load_pem_cert("server_cert.pem")
    ca_cert = load_pem_cert("ca_cert.pem")
    HOST = '0.0.0.0';
    PORT = 5555
    s = socket.socket()
    s.bind((HOST, PORT));
    s.listen(5)
    print("listening", HOST, PORT)
    try:
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_conn, args=(conn, addr, server_priv, server_cert, ca_cert), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("bye")
    finally:
        s.close()


if __name__ == "__main__":
    main()