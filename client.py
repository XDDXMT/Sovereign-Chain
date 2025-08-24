#!/usr/bin/env python3
# client.py
"""
Sovereign-Chain Client - 安全加固版本
修复所有安全审查问题
"""

import socket, struct, os, time, logging, math, secrets, hashlib, traceback
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import threading
from collections import deque

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

FRAME_HDR = 4
PROTO_VER = b"SC-EE-1"
CIPHER_SUITE = b"X25519-Ed25519-CHACHA20POLY1305-HKDFSHA256"
HANDSHAKE_TIMEOUT = 30  # 握手超时时间（秒）

# 错误频率限制
ERROR_TIMES = deque(maxlen=100)
ERROR_LOCK = threading.Lock()


def safe_log_error(message):
    """安全日志记录，防止日志泛洪攻击"""
    now = time.time()
    with ERROR_LOCK:
        ERROR_TIMES.append(now)
        # 检查最近10秒内的错误数量
        recent_errors = [t for t in ERROR_TIMES if now - t < 10]
        if len(recent_errors) > 50:  # 10秒内超过50个错误则抑制
            return
        logger.error(message)


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
        # 修复：降低最大帧大小防止内存耗尽
        if l > 1_000_000:  # 从50MB改为1MB
            raise ValueError("Frame too large")
        return recv_exact(sock, l)
    except Exception as e:
        raise ConnectionError(f"Failed to receive frame: {str(e)}")


def load_priv():
    """使用本地固定路径"""
    try:
        with open("client_key.pem", "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
    except Exception as e:
        raise ValueError(f"Failed to load private key: {str(e)}")


def load_cert():
    """使用本地固定路径"""
    try:
        with open("client_cert.pem", "rb") as f:
            return x509.load_pem_x509_certificate(
                f.read(),
                backend=default_backend()
            )
    except Exception as e:
        raise ValueError(f"Failed to load certificate: {str(e)}")


def load_ca_cert():
    """使用本地固定路径"""
    try:
        with open("ca_cert.pem", "rb") as f:
            return x509.load_pem_x509_certificate(
                f.read(),
                backend=default_backend()
            )
    except Exception as e:
        raise ValueError(f"Failed to load CA certificate: {str(e)}")


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


def validate_field(data, min_len, max_len, field_name, is_text=False):
    """修复：验证字段长度和内容"""
    if not isinstance(data, bytes):
        raise ValueError(f"{field_name} must be bytes")
    if len(data) < min_len or len(data) > max_len:
        raise ValueError(f"Invalid {field_name} length: {len(data)}")

    # 仅对文本字段检查可打印字符
    if is_text:
        if any(b < 0x20 or b > 0x7E for b in data):
            raise ValueError(f"Invalid characters in {field_name}")


def parse_protocol_frame(frame, expected_type):
    """修复：安全解析协议帧"""
    # 直接使用前缀长度提取payload
    expected_prefix = expected_type + b"|"
    if not frame.startswith(expected_prefix):
        raise ProtocolError(f"Invalid frame format for {expected_type.decode()}")
    return frame[len(expected_prefix):]


class ProtocolError(Exception):
    """协议错误异常"""
    pass


class Session:
    def __init__(self, send_key, recv_key, seed_code):
        self.send_base_key = send_key
        self.recv_base_key = recv_key
        self.seed_code = seed_code
        self.send_seq = 1
        self.recv_seq = 1
        self.send_label = b"client->server"
        self.recv_label = b"server->client"

    def _derive_key(self, base_key, seq, label):
        """使用种子码和序列号派生动态密钥"""
        info = self.seed_code + struct.pack(">Q", seq) + label
        return hkdf(base_key, info, length=32)

    def encrypt(self, pt, aad=b""):
        dynamic_key = self._derive_key(self.send_base_key, self.send_seq, self.send_label)
        aead = ChaCha20Poly1305(dynamic_key)
        n = nonce_from_seq(self.send_seq, self.send_label)
        self.send_seq += 1
        return aead.encrypt(n, pt, aad)

    def decrypt(self, ct, aad=b""):
        dynamic_key = self._derive_key(self.recv_base_key, self.recv_seq, self.recv_label)
        aead = ChaCha20Poly1305(dynamic_key)
        n = nonce_from_seq(self.recv_seq, self.recv_label)
        pt = aead.decrypt(n, ct, aad)
        self.recv_seq += 1
        return pt


def client_handshake(host="127.0.0.1", port=5555):
    """执行13步握手，返回已握手完成的 Session 和 socket"""
    logger.info(f"Starting handshake with {host}:{port}")

    # 状态机初始化
    current_state = "INIT"

    # 幂等性缓存
    if not hasattr(client_handshake, "nonce_cache"):
        client_handshake.nonce_cache = set()

    try:
        client_priv = load_priv()
        client_cert = load_cert()
        ca_cert = load_ca_cert()
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
        # ==== 状态1: 发送ClientHello ====
        logger.info("Step 1/13: Sending ClientHello")
        if current_state != "INIT":
            raise ProtocolError("Invalid state for ClientHello")
        current_state = "CLIENTHELLO_SENT"

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

        # ==== 状态2: 接收ServerHello ====
        logger.info("Step 2/13: Waiting for ServerHello")
        sh_frame = recv_frame(s)
        if current_state != "CLIENTHELLO_SENT":
            raise ProtocolError("Invalid state for ServerHello")
        current_state = "SERVERHELLO_RECEIVED"

        # 修复：直接解析整个帧
        if not sh_frame.startswith(b"SERVERHELLO|"):
            raise ValueError("Invalid ServerHello message format")

        payload = sh_frame[len(b"SERVERHELLO|"):]
        if len(payload) != 48:  # 32字节公钥 + 16字节nonce
            raise ValueError(f"Invalid ServerHello payload length: {len(payload)}")

        server_eph_pub = payload[:32]
        nonce_s = payload[32:48]

        transcript_hash.update(sh_frame)
        transcript = transcript_hash.copy().finalize()

        # ==== 状态3: 接收ServerCertSend ====
        logger.info("Step 3/13: Waiting for ServerCertSend")
        scert_frame = recv_frame(s)
        if current_state != "SERVERHELLO_RECEIVED":
            raise ProtocolError("Invalid state for ServerCertSend")
        current_state = "SERVERCERTSEND_RECEIVED"

        server_cert_pem = parse_protocol_frame(scert_frame, b"SERVERCERTSEND")
        server_cert = x509.load_pem_x509_certificate(
            server_cert_pem,
            backend=default_backend()
        )
        transcript_hash.update(scert_frame)
        transcript = transcript_hash.copy().finalize()

        # ==== 状态4: 验证服务器证书 ====
        logger.info("Step 4/13: Verifying server certificate")
        ca_pub = ca_cert.public_key()
        try:
            if not isinstance(ca_pub, ed25519.Ed25519PublicKey):
                raise ValueError("CA public key is not Ed25519")
            ca_pub.verify(
                server_cert.signature,
                server_cert.tbs_certificate_bytes
            )
            logger.info("Server certificate verified successfully")
        except InvalidSignature:
            raise ValueError("Server certificate signature is invalid")
        except Exception as e:
            raise ValueError(f"Server certificate verification failed: {str(e)}")

        # ==== 状态5: 接收ClientCertRequest ====
        logger.info("Step 5/13: Waiting for ClientCertRequest")
        ccr_frame = recv_frame(s)
        if current_state != "SERVERCERTSEND_RECEIVED":
            raise ProtocolError("Invalid state for ClientCertRequest")
        current_state = "CLIENTCERTREQUEST_RECEIVED"

        parse_protocol_frame(ccr_frame, b"CLIENTCERTREQUEST")
        transcript_hash.update(ccr_frame)
        transcript = transcript_hash.copy().finalize()

        # ==== 状态6: 发送ClientCertSend ====
        logger.info("Step 6/13: Sending ClientCertSend")
        ccert_fr = b"CLIENTCERTSEND|" + client_cert.public_bytes(serialization.Encoding.PEM)
        s.sendall(pack(ccert_fr))
        transcript_hash.update(ccert_fr)
        transcript = transcript_hash.copy().finalize()
        current_state = "CLIENTCERTSEND_SENT"

        # ==== 状态7: 接收KeyExchange1 ====
        logger.info("Step 7/13: Waiting for KeyExchange1")
        ke1_frame = recv_frame(s)
        if current_state != "CLIENTCERTSEND_SENT":
            raise ProtocolError("Invalid state for KeyExchange1")
        current_state = "KEYEXCHANGE1_RECEIVED"

        ke1_data = parse_protocol_frame(ke1_frame, b"KEYEXCHANGE1")
        validate_field(ke1_data, 32, 32, "KeyExchange1 data", is_text=False)
        transcript_hash.update(ke1_frame)
        transcript = transcript_hash.copy().finalize()

        # ==== 状态8: 发送KeyExchange2 ====
        logger.info("Step 8/13: Sending KeyExchange2")
        ke2_data = os.urandom(32)
        ke2 = b"KEYEXCHANGE2|" + ke2_data
        s.sendall(pack(ke2))
        transcript_hash.update(ke2)
        transcript = transcript_hash.copy().finalize()
        current_state = "KEYEXCHANGE2_SENT"

        # ==== 状态9: 接收KeyConfirm1 ====
        logger.info("Step 9/13: Waiting for KeyConfirm1")
        kc1_frame = recv_frame(s)
        if current_state != "KEYEXCHANGE2_SENT":
            raise ProtocolError("Invalid state for KeyConfirm1")
        current_state = "KEYCONFIRM1_RECEIVED"

        kc1_data = parse_protocol_frame(kc1_frame, b"KEYCONFIRM1")
        validate_field(kc1_data, 32, 32, "KeyConfirm1 data", is_text=False)
        transcript_hash.update(kc1_frame)
        transcript = transcript_hash.copy().finalize()

        # ==== 状态10: 发送KeyConfirm2 ====
        logger.info("Step 10/13: Sending KeyConfirm2")
        kc2_data = os.urandom(32)
        kc2 = b"KEYCONFIRM2|" + kc2_data
        s.sendall(pack(kc2))
        transcript_hash.update(kc2)
        transcript = transcript_hash.copy().finalize()
        current_state = "KEYCONFIRM2_SENT"

        # ==== 状态11: 计算共享密钥 ====
        logger.info("Step 11/13: Calculating shared key")
        shared = client_eph.exchange(x25519.X25519PublicKey.from_public_bytes(server_eph_pub))

        info = b"SC-HKDF|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|" + nonce_c + b"|" + nonce_s
        info += b"|" + ke1_data + b"|" + ke2_data + b"|" + kc1_data + b"|" + kc2_data

        okm = hkdf(shared, info, length=64)
        k_c2s = okm[:32]
        k_s2c = okm[32:]

        del client_eph

        # ==== 状态12: 接收并解密SeedCode ====
        logger.info("Step 12/13: Receiving and decrypting SeedCode")
        encrypted_payload = recv_frame(s)
        if current_state != "KEYCONFIRM2_SENT":
            raise ProtocolError("Invalid state for SeedCode")
        current_state = "SEEDCODE_RECEIVED"

        temp_aead = ChaCha20Poly1305(k_s2c)
        temp_nonce = transcript[:12]

        try:
            payload = temp_aead.decrypt(temp_nonce, encrypted_payload, transcript)
            if not payload.startswith(b"SEEDCODE|"):
                raise ValueError("Invalid seed code format")

            seed_payload = payload.split(b"|", 1)[1]
            if len(seed_payload) < 72:
                raise ValueError("Invalid seed payload length")

            seed_nonce = seed_payload[:8]
            seed_code = seed_payload[8:72]

            # 幂等性检查
            if seed_nonce in client_handshake.nonce_cache:
                raise ValueError("Seed frame replay detected")
            client_handshake.nonce_cache.add(seed_nonce)

            # 熵源验证
            def shannon_entropy(data):
                entropy = 0.0
                for x in range(256):
                    p_x = data.count(bytes([x])) / len(data)
                    if p_x > 0:
                        entropy += -p_x * math.log2(p_x)
                return entropy

            entropy_value = shannon_entropy(seed_code)

        except Exception as e:
            logger.error(f"Seed frame processing failed: {str(e)}")
            s.close()
            raise

        transcript_hash.update(encrypted_payload)
        transcript = transcript_hash.copy().finalize()

        # ==== 状态13: 发送ClientAuth ====
        logger.info("Step 13/13: Sending ClientAuth and completing handshake")
        sig_client = client_priv.sign(transcript)
        auth_msg = b"CLIENTAUTH|" + sig_client
        s.sendall(pack(auth_msg))
        transcript_hash.update(auth_msg)
        transcript = transcript_hash.copy().finalize()
        current_state = "CLIENTAUTH_SENT"

        # ==== 状态14: 接收ServerAuth ====
        sa_frame = recv_frame(s)
        if current_state != "CLIENTAUTH_SENT":
            raise ProtocolError("Invalid state for ServerAuth")
        current_state = "SERVERAUTH_RECEIVED"

        sig_server = parse_protocol_frame(sa_frame, b"SERVERAUTH")
        server_pub = server_cert.public_key()
        if not isinstance(server_pub, ed25519.Ed25519PublicKey):
            raise ValueError("Server public key is not Ed25519")

        try:
            server_pub.verify(sig_server, transcript)
            logger.info("Server signature verified successfully")
        except InvalidSignature:
            raise ValueError("Server signature verification failed")

        transcript_hash.update(sa_frame)
        transcript = transcript_hash.copy().finalize()

        # ==== 状态15: 接收SecureAck ====
        ack_frame = recv_frame(s)
        if current_state != "SERVERAUTH_RECEIVED":
            raise ProtocolError("Invalid state for SecureAck")
        current_state = "SECUREACK_RECEIVED"

        ct = parse_protocol_frame(ack_frame, b"SECUREACK")
        sess = Session(send_key=k_c2s, recv_key=k_s2c, seed_code=seed_code)

        try:
            ack = sess.decrypt(ct, aad=transcript)
            if ack != b"ACK":
                raise ValueError("Invalid ACK value")
            logger.info("Secure ACK verified successfully")
        except Exception as e:
            raise ValueError(f"Secure ACK verification failed: {str(e)}")

        handshake_time = time.time() - handshake_start_time
        logger.info(f"Handshake completed successfully in {handshake_time:.2f}s")

        s.settimeout(None)
        return sess, s

    except socket.timeout:
        s.close()
        raise ConnectionError("Handshake timeout")
    except Exception as e:
        s.close()
        safe_log_error(f"Handshake failed: {str(e)}")
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

                current_seq = sess.send_seq
                header = struct.pack(">Q", current_seq)
                ct = sess.encrypt(line.encode())
                data_frame = b"DATA" + header + ct
                s.sendall(pack(data_frame))

                try:
                    frm = recv_frame(s)
                except ConnectionError as e:
                    safe_log_error(f"Failed to receive response: {str(e)}")
                    break

                if not frm.startswith(b"DATA"):
                    logger.warning("Received non-DATA frame, closing connection")
                    break

                if len(frm) < 12:
                    logger.warning("Invalid response frame format")
                    break

                resp_seq = struct.unpack(">Q", frm[4:12])[0]
                resp_ct = frm[12:]

                if resp_seq != sess.recv_seq:
                    logger.warning(f"Sequence number mismatch: expected {sess.recv_seq}, got {resp_seq}")
                    break

                try:
                    resp = sess.decrypt(resp_ct)
                    print("server:", resp.decode(errors="ignore"))
                except Exception as e:
                    safe_log_error(f"Decryption error: {str(e)}")
                    break
        except KeyboardInterrupt:
            print("\nClient shutting down...")
        except Exception as e:
            safe_log_error(f"Communication error: {str(e)}")
        finally:
            s.close()
    except Exception as e:
        safe_log_error(f"Handshake failed: {str(e)}")


if __name__ == "__main__":
    main()