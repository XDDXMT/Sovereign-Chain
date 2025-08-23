#!/usr/bin/env python3
# client.py
"""
Sovereign-Chain Client - 12次超级无敌宇宙加密握手版本
按 server 的 12 步握手顺序执行：
1) CLIENTHELLO      : client_eph_pub || nonce_c
2) recv SERVERHELLO : server_eph_pub || nonce_s
3) recv SERVERCERTSEND: server_cert PEM
4) recv CLIENTCERTREQUEST: 请求客户端证书
5) send CLIENTCERTSEND: client_cert PEM
6) recv KEYEXCHANGE1: 额外的密钥交换数据1
7) send KEYEXCHANGE2: 额外的密钥交换数据2
8) recv KEYCONFIRM1 : 密钥确认数据1
9) send KEYCONFIRM2 : 密钥确认数据2
10) send CLIENTAUTH : signature_client(transcript)
11) recv SERVERAUTH : signature_server(transcript)  (verify)
12) recv SECUREACK  : decrypt ACK using derived keys (with aad=transcript)
随后发送/接收 DATA|<ct> 帧
"""

import socket, struct, os
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography import x509

FRAME_HDR = 4
PROTO_VER = b"SC-EE-1"
CIPHER_SUITE = b"X25519-Ed25519-CHACHA20POLY1305-HKDFSHA256"


def pack(b): return struct.pack(">I", len(b)) + b


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        r = sock.recv(n - len(buf))
        if not r: raise ConnectionError("closed")
        buf += r
    return buf


def recv_frame(sock):
    hdr = recv_exact(sock, FRAME_HDR);
    (l,) = struct.unpack(">I", hdr);
    return recv_exact(sock, l)


def load_priv(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def hkdf(ikm, info, length=64):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(ikm)


def nonce_from_seq(seq: int, label: bytes):
    h = hashes.Hash(hashes.SHA256());
    h.update(label);
    prefix = h.finalize()[:4]
    import struct as _s;
    return prefix + _s.pack(">Q", seq)


class Session:
    def __init__(self, send_key, recv_key):
        self.send_aead = ChaCha20Poly1305(send_key);
        self.recv_aead = ChaCha20Poly1305(recv_key)
        self.send_seq = 0;
        self.recv_seq = 0;
        self.send_label = b"client->server";
        self.recv_label = b"server->client"

    def encrypt(self, pt, aad=b""):
        n = nonce_from_seq(self.send_seq, self.send_label);
        self.send_seq += 1;
        return self.send_aead.encrypt(n, pt, aad)

    def decrypt(self, ct, aad=b""):
        n = nonce_from_seq(self.recv_seq, self.recv_label);
        pt = self.recv_aead.decrypt(n, ct, aad);
        self.recv_seq += 1;
        return pt


def main():
    client_priv = load_priv("client_key.pem")
    client_cert = load_cert("client_cert.pem")
    ca_cert = load_cert("ca_cert.pem")

    s = socket.create_connection(("127.0.0.1", 5555))
    try:
        # 1) CLIENTHELLO
        client_eph = x25519.X25519PrivateKey.generate()
        client_eph_pub = client_eph.public_key().public_bytes(serialization.Encoding.Raw,
                                                              serialization.PublicFormat.Raw)
        nonce_c = os.urandom(16)
        ch = b"CLIENTHELLO|" + client_eph_pub + nonce_c
        s.sendall(pack(ch))
        transcript = ch

        # 2) SERVERHELLO
        sh = recv_frame(s)
        if not sh.startswith(b"SERVERHELLO|"): raise ValueError("bad serverhello")
        payload = sh.split(b"|", 1)[1]
        server_eph_pub = payload[:32];
        nonce_s = payload[32:48]
        transcript += sh

        # 3) SERVERCERTSEND
        scert = recv_frame(s)
        if not scert.startswith(b"SERVERCERTSEND|"): raise ValueError("bad servercertsend")
        server_cert_pem = scert.split(b"|", 1)[1]
        server_cert = x509.load_pem_x509_certificate(server_cert_pem)
        transcript += scert

        # 验证服务器证书
        ca_pub = ca_cert.public_key()
        ca_pub.verify(server_cert.signature, server_cert.tbs_certificate_bytes)

        # 4) CLIENTCERTREQUEST
        ccr = recv_frame(s)
        if not ccr.startswith(b"CLIENTCERTREQUEST|"): raise ValueError("bad clientcertrequest")
        transcript += ccr

        # 5) CLIENTCERTSEND
        ccert_fr = b"CLIENTCERTSEND|" + client_cert.public_bytes(serialization.Encoding.PEM)
        s.sendall(pack(ccert_fr))
        transcript += ccert_fr

        # 6) KEYEXCHANGE1
        ke1 = recv_frame(s)
        if not ke1.startswith(b"KEYEXCHANGE1|"): raise ValueError("bad keyexchange1")
        ke1_data = ke1.split(b"|", 1)[1]
        transcript += ke1

        # 7) KEYEXCHANGE2
        ke2_data = os.urandom(32)
        ke2 = b"KEYEXCHANGE2|" + ke2_data
        s.sendall(pack(ke2))
        transcript += ke2

        # 8) KEYCONFIRM1
        kc1 = recv_frame(s)
        if not kc1.startswith(b"KEYCONFIRM1|"): raise ValueError("bad keyconfirm1")
        kc1_data = kc1.split(b"|", 1)[1]
        transcript += kc1

        # 9) KEYCONFIRM2
        kc2_data = os.urandom(32)
        kc2 = b"KEYCONFIRM2|" + kc2_data
        s.sendall(pack(kc2))
        transcript += kc2

        # 计算共享密钥（包含额外的密钥交换数据）
        shared = client_eph.exchange(x25519.X25519PublicKey.from_public_bytes(server_eph_pub))
        # 将额外的密钥交换数据加入密钥派生
        extra_key_material = ke1_data + ke2_data + kc1_data + kc2_data
        info = b"SC-HKDF" + PROTO_VER + CIPHER_SUITE + nonce_c + nonce_s + extra_key_material
        okm = hkdf(shared, info, length=64)
        k_c2s = okm[:32];
        k_s2c = okm[32:]

        # 10) CLIENTAUTH: sign transcript
        sig_client = client_priv.sign(transcript)
        s.sendall(pack(b"CLIENTAUTH|" + sig_client))
        transcript += b"CLIENTAUTH|" + sig_client

        # 11) SERVERAUTH (verify)
        sa = recv_frame(s)
        if not sa.startswith(b"SERVERAUTH|"): raise ValueError("missing serverauth")
        sig_server = sa.split(b"|", 1)[1]
        server_pub = server_cert.public_key()
        server_pub.verify(sig_server, transcript)
        transcript += sa

        # 12) SECUREACK (encrypted)
        ack_fr = recv_frame(s)
        if not ack_fr.startswith(b"SECUREACK|"): raise ValueError("missing secureack")
        ct = ack_fr.split(b"|", 1)[1]
        sess = Session(send_key=k_c2s, recv_key=k_s2c)
        ack = sess.decrypt(ct, aad=transcript)
        if ack != b"ACK": raise ValueError("bad ack")
        print("[client] 12次握手完成，安全通道已建立")

        # 交互发送明文 -> 加密 -> send; receive decrypt
        import sys
        while True:
            line = input("msg> ")
            if not line: continue
            pt = line.encode()
            s.sendall(pack(b"DATA|" + sess.encrypt(pt)))
            frm = recv_frame(s)
            if not frm.startswith(b"DATA|"): break
            resp_ct = frm.split(b"|", 1)[1]
            resp = sess.decrypt(resp_ct)
            print("server:", resp.decode(errors="ignore"))
    finally:
        s.close()


if __name__ == "__main__":
    main()