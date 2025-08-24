#!/usr/bin/env python3
# client.py
"""
Sovereign-Chain Client - 12次超级无敌宇宙加密握手版本 + 种子码动态加密
提供 client_handshake(host, port) 供 client_proxy.py 调用
"""

import socket, struct, os, time, logging
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

FRAME_HDR = 4
PROTO_VER = b"SC-EE-1"
CIPHER_SUITE = b"X25519-Ed25519-CHACHA20POLY1305-HKDFSHA256"
HANDSHAKE_TIMEOUT = 30  # 握手超时时间（秒）


def pack(b):
    return struct.pack(">I", len(b)) + b


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            r = sock.recv(n - len(buf))
            if not r:
                raise ConnectionError("Connection closed by peer")
            buf += r
        except socket.timeout:
            raise ConnectionError("Receive timeout")
        except ConnectionResetError:
            raise ConnectionError("Connection reset by peer")
    return buf


def recv_frame(sock):
    try:
        hdr = recv_exact(sock, FRAME_HDR)
        (l,) = struct.unpack(">I", hdr)
        if l > 50_000_000:
            raise ValueError("Frame too large")
        return recv_exact(sock, l)
    except Exception as e:
        raise ConnectionError(f"Failed to receive frame: {str(e)}")


def load_priv(path):
    try:
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
    except Exception as e:
        raise ValueError(f"Failed to load private key: {str(e)}")


def load_cert(path):
    try:
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(
                f.read(),
                backend=default_backend()
            )
    except Exception as e:
        raise ValueError(f"Failed to load certificate: {str(e)}")


def hkdf(ikm, info, length=64):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
        backend=default_backend()
    ).derive(ikm)


def nonce_from_seq(seq: int, label: bytes):
    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    h.update(label)
    prefix = h.finalize()[:4]
    return prefix + struct.pack(">Q", seq)


class Session:
    def __init__(self, send_key, recv_key, seed_code):
        self.send_base_key = send_key
        self.recv_base_key = recv_key
        self.seed_code = seed_code
        self.send_seq = 0
        self.recv_seq = 0
        self.send_label = b"client->server"
        self.recv_label = b"server->client"

    def _derive_key(self, base_key, seq, label):
        """使用种子码和序列号派生动态密钥"""
        info = self.seed_code + struct.pack(">Q", seq) + label
        return hkdf(base_key, info, length=32)

    def encrypt(self, pt, aad=b""):
        # 派生本次消息的动态密钥
        dynamic_key = self._derive_key(self.send_base_key, self.send_seq, self.send_label)
        aead = ChaCha20Poly1305(dynamic_key)

        n = nonce_from_seq(self.send_seq, self.send_label)
        self.send_seq += 1
        return aead.encrypt(n, pt, aad)

    def decrypt(self, ct, aad=b""):
        # 派生本次消息的动态密钥
        dynamic_key = self._derive_key(self.recv_base_key, self.recv_seq, self.recv_label)
        aead = ChaCha20Poly1305(dynamic_key)

        n = nonce_from_seq(self.recv_seq, self.recv_label)
        pt = aead.decrypt(n, ct, aad)
        self.recv_seq += 1
        return pt


def client_handshake(host="127.0.0.1", port=5555):
    """执行13步握手，返回已握手完成的 Session 和 socket"""
    logger.info(f"Starting handshake with {host}:{port}")

    try:
        client_priv = load_priv("client_key.pem")
        client_cert = load_cert("client_cert.pem")
        ca_cert = load_cert("ca_cert.pem")
    except Exception as e:
        raise ConnectionError(f"Failed to load credentials: {str(e)}")

    try:
        s = socket.create_connection((host, port))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        s.settimeout(HANDSHAKE_TIMEOUT)
    except Exception as e:
        raise ConnectionError(f"Failed to connect to server: {str(e)}")

    handshake_start_time = time.time()
    transcript_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())

    try:
        logger.info("Step 1/13: Sending ClientHello")
        # 1) CLIENTHELLO
        client_eph = x25519.X25519PrivateKey.generate()
        client_eph_pub = client_eph.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
        nonce_c = os.urandom(16)
        ch = b"CLIENTHELLO|" + client_eph_pub + nonce_c
        s.sendall(pack(ch))
        transcript_hash.update(ch)
        transcript = transcript_hash.copy().finalize()

        logger.info("Step 2/13: Waiting for ServerHello")
        # 2) SERVERHELLO
        sh = recv_frame(s)
        if not sh.startswith(b"SERVERHELLO|"):
            raise ValueError("Invalid ServerHello message format")
        payload = sh.split(b"|", 1)[1]
        if len(payload) != 48:  # 32字节公钥 + 16字节nonce
            raise ValueError("Invalid ServerHello payload length")

        server_eph_pub = payload[:32]
        nonce_s = payload[32:48]
        transcript_hash.update(sh)
        transcript = transcript_hash.copy().finalize()

        logger.info("Step 3/13: Waiting for ServerCertSend")
        # 3) SERVERCERTSEND
        scert = recv_frame(s)
        if not scert.startswith(b"SERVERCERTSEND|"):
            raise ValueError("Invalid ServerCertSend message format")
        server_cert_pem = scert.split(b"|", 1)[1]
        server_cert = x509.load_pem_x509_certificate(
            server_cert_pem,
            backend=default_backend()
        )
        transcript_hash.update(scert)
        transcript = transcript_hash.copy().finalize()

        logger.info("Step 4/13: Verifying server certificate")
        # 验证服务器证书
        ca_pub = ca_cert.public_key()
        try:
            # 验证证书签名
            if not isinstance(ca_pub, ed25519.Ed25519PublicKey):
                raise ValueError("CA public key is not Ed25519")

            # 对于Ed25519，直接验证签名
            ca_pub.verify(
                server_cert.signature,
                server_cert.tbs_certificate_bytes
            )
            logger.info("Server certificate verified successfully")
        except InvalidSignature:
            raise ValueError("Server certificate signature is invalid")
        except Exception as e:
            raise ValueError(f"Server certificate verification failed: {str(e)}")

        logger.info("Step 5/13: Waiting for ClientCertRequest")
        # 4) CLIENTCERTREQUEST
        ccr = recv_frame(s)
        if not ccr.startswith(b"CLIENTCERTREQUEST|"):
            raise ValueError("Invalid ClientCertRequest message format")
        transcript_hash.update(ccr)
        transcript = transcript_hash.copy().finalize()

        logger.info("Step 6/13: Sending ClientCertSend")
        # 5) CLIENTCERTSEND
        ccert_fr = b"CLIENTCERTSEND|" + client_cert.public_bytes(serialization.Encoding.PEM)
        s.sendall(pack(ccert_fr))
        transcript_hash.update(ccert_fr)
        transcript = transcript_hash.copy().finalize()

        logger.info("Step 7/13: Waiting for KeyExchange1")
        # 6) KEYEXCHANGE1
        ke1 = recv_frame(s)
        if not ke1.startswith(b"KEYEXCHANGE1|"):
            raise ValueError("Invalid KeyExchange1 message format")
        ke1_data = ke1.split(b"|", 1)[1]
        if len(ke1_data) != 32:
            raise ValueError("Invalid KeyExchange1 data length")
        transcript_hash.update(ke1)
        transcript = transcript_hash.copy().finalize()

        logger.info("Step 8/13: Sending KeyExchange2")
        # 7) KEYEXCHANGE2
        ke2_data = os.urandom(32)
        ke2 = b"KEYEXCHANGE2|" + ke2_data
        s.sendall(pack(ke2))
        transcript_hash.update(ke2)
        transcript = transcript_hash.copy().finalize()

        logger.info("Step 9/13: Waiting for KeyConfirm1")
        # 8) KEYCONFIRM1
        kc1 = recv_frame(s)
        if not kc1.startswith(b"KEYCONFIRM1|"):
            raise ValueError("Invalid KeyConfirm1 message format")
        kc1_data = kc1.split(b"|", 1)[1]
        if len(kc1_data) != 32:
            raise ValueError("Invalid KeyConfirm1 data length")
        transcript_hash.update(kc1)
        transcript = transcript_hash.copy().finalize()

        logger.info("Step 10/13: Sending KeyConfirm2")
        # 9) KEYCONFIRM2
        kc2_data = os.urandom(32)
        kc2 = b"KEYCONFIRM2|" + kc2_data
        s.sendall(pack(kc2))
        transcript_hash.update(kc2)
        transcript = transcript_hash.copy().finalize()

        logger.info("Step 11/13: Calculating shared key")
        # 计算共享密钥（包含额外的密钥交换数据）
        shared = client_eph.exchange(x25519.X25519PublicKey.from_public_bytes(server_eph_pub))

        # 使用结构化的info参数进行密钥派生
        info = b"SC-HKDF|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|" + nonce_c + b"|" + nonce_s
        info += b"|" + ke1_data + b"|" + ke2_data + b"|" + kc1_data + b"|" + kc2_data

        okm = hkdf(shared, info, length=64)
        k_c2s = okm[:32]
        k_s2c = okm[32:]

        # 销毁临时密钥以确保前向安全性
        del client_eph

        # ==== 新增：接收种子码 ====
        logger.info("Step 12/13: Receiving SeedCode")
        seed_frame = recv_frame(s)
        if not seed_frame.startswith(b"SEEDCODE|"):
            raise ValueError("Invalid SeedCode message format")
        seed_code = seed_frame.split(b"|", 1)[1]
        if len(seed_code) != 32:
            raise ValueError("Invalid SeedCode length")
        transcript_hash.update(seed_frame)
        transcript = transcript_hash.copy().finalize()

        logger.info("Step 13/13: Sending ClientAuth and completing handshake")
        # 10) CLIENTAUTH: sign transcript
        sig_client = client_priv.sign(transcript)
        auth_msg = b"CLIENTAUTH|" + sig_client
        s.sendall(pack(auth_msg))
        transcript_hash.update(auth_msg)
        transcript = transcript_hash.copy().finalize()

        # 11) SERVERAUTH (verify)
        sa = recv_frame(s)
        if not sa.startswith(b"SERVERAUTH|"):
            raise ValueError("Invalid ServerAuth message format")
        sig_server = sa.split(b"|", 1)[1]
        server_pub = server_cert.public_key()
        if not isinstance(server_pub, ed25519.Ed25519PublicKey):
            raise ValueError("Server public key is not Ed25519")

        try:
            server_pub.verify(sig_server, transcript)
            logger.info("Server signature verified successfully")
        except InvalidSignature:
            raise ValueError("Server signature verification failed")

        transcript_hash.update(sa)
        transcript = transcript_hash.copy().finalize()

        # 12) SECUREACK (encrypted)
        ack_fr = recv_frame(s)
        if not ack_fr.startswith(b"SECUREACK|"):
            raise ValueError("Invalid SecureAck message format")
        ct = ack_fr.split(b"|", 1)[1]
        # 使用种子码创建会话
        sess = Session(send_key=k_c2s, recv_key=k_s2c, seed_code=seed_code)

        # 验证ACK
        try:
            ack = sess.decrypt(ct, aad=transcript)
            if ack != b"ACK":
                raise ValueError("Invalid ACK value")
            logger.info("Secure ACK verified successfully")
        except Exception as e:
            raise ValueError(f"Secure ACK verification failed: {str(e)}")

        handshake_time = time.time() - handshake_start_time
        logger.info(f"Handshake completed successfully in {handshake_time:.2f}s")

        # 重置超时设置
        s.settimeout(None)

        return sess, s

    except socket.timeout:
        s.close()
        raise ConnectionError("Handshake timeout")
    except Exception as e:
        s.close()
        raise ConnectionError(f"Handshake failed: {str(e)}")


def main():
    try:
        sess, s = client_handshake("127.0.0.1", 5555)
        logger.info("Starting secure communication")
        try:
            while True:
                line = input("msg> ")
                if not line:
                    continue
                s.sendall(pack(b"DATA|" + sess.encrypt(line.encode())))
                frm = recv_frame(s)
                if not frm.startswith(b"DATA|"):
                    logger.warning("Received non-DATA frame, closing connection")
                    break
                resp_ct = frm.split(b"|", 1)[1]
                resp = sess.decrypt(resp_ct)
                print("server:", resp.decode(errors="ignore"))
        except KeyboardInterrupt:
            print("\nClient shutting down...")
        except Exception as e:
            logger.error(f"Communication error: {str(e)}")
        finally:
            s.close()
    except Exception as e:
        logger.error(f"Handshake failed: {str(e)}")


if __name__ == "__main__":
    main()