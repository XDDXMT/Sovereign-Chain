#!/usr/bin/env python3
# server.py
"""
Sovereign-Chain Server - 支持匿名客户端
"""

import socket, struct, os, threading, time, logging, math, secrets
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import hashlib
from collections import deque

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

FRAME_HDR = 4
PROTO_VER = b"SC-EE-1"
CIPHER_SUITE = b"X25519-Ed25519-CHACHA20POLY1305-HKDFSHA256"
HANDSHAKE_TIMEOUT = 30  # 握手超时时间（秒）

# 连接和计算资源限制
MAX_CONNECTIONS = 100
CONNECTION_SEMAPHORE = threading.Semaphore(MAX_CONNECTIONS)
COMPUTE_SEM = threading.Semaphore(50)  # 限制并发计算量

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


# 用于防止重放攻击的nonce缓存
nonce_cache = {}
nonce_cache_lock = threading.Lock()
NONCE_CACHE_MAX_SIZE = 10000
NONCE_CACHE_EXPIRE = 300  # 5分钟


class ProtocolError(Exception):
    """协议错误异常"""
    pass


class SequenceError(Exception):
    """序列号验证失败异常"""
    pass


def pack(buf: bytes) -> bytes:
    return struct.pack(">I", len(buf)) + buf


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            r = sock.recv(n - len(buf))
            if not r:
                raise ConnectionError("peer closed")
            buf += r
        except socket.timeout:
            raise ConnectionError("receive timeout")
        except ConnectionResetError:
            raise ConnectionError("connection reset by peer")
    return buf


def recv_frame(sock):
    try:
        hdr = recv_exact(sock, FRAME_HDR)
        (l,) = struct.unpack(">I", hdr)
        # 修复：降低最大帧大小防止内存耗尽
        if l > 1_000_000:  # 从50MB改为1MB
            raise ValueError("frame too large")
        return recv_exact(sock, l)
    except Exception as e:
        raise ConnectionError(f"failed to receive frame: {str(e)}")


def load_pem_priv():
    """使用本地固定路径"""
    try:
        with open("server_key.pem", "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
    except Exception as e:
        raise ValueError(f"failed to load private key: {str(e)}")


def load_pem_cert():
    """使用本地固定路径"""
    try:
        with open("server_cert.pem", "rb") as f:
            return x509.load_pem_x509_certificate(
                f.read(),
                backend=default_backend()
            )
    except Exception as e:
        raise ValueError(f"failed to load certificate: {str(e)}")


def load_ca_cert():
    """使用本地固定路径"""
    try:
        with open("ca_cert.pem", "rb") as f:
            return x509.load_pem_x509_certificate(
                f.read(),
                backend=default_backend()
            )
    except Exception as e:
        raise ValueError(f"failed to load CA certificate: {str(e)}")


def load_anonymous_ca_cert():
    """加载匿名CA证书"""
    try:
        with open("anonymous_ca_cert.pem", "rb") as f:
            return x509.load_pem_x509_certificate(
                f.read(),
                backend=default_backend()
            )
    except Exception as e:
        raise ValueError(f"failed to load anonymous CA certificate: {str(e)}")


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


def check_nonce_replay(nonce, addr):
    """检查nonce是否重复使用"""
    current_time = time.time()
    with nonce_cache_lock:
        # 清理过期nonce
        for key, (timestamp, _) in list(nonce_cache.items()):
            if current_time - timestamp > NONCE_CACHE_EXPIRE:
                del nonce_cache[key]

        # 检查缓存大小
        if len(nonce_cache) > NONCE_CACHE_MAX_SIZE:
            # 如果缓存满了，清除最旧的10%
            items = sorted(nonce_cache.items(), key=lambda x: x[1][0])
            for key in items[:len(items) // 10]:
                del nonce_cache[key]

        # 检查nonce是否已存在
        if nonce in nonce_cache:
            return False

        # 记录新nonce
        nonce_cache[nonce] = (current_time, addr)
        return True


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


class Session:
    def __init__(self, send_key, recv_key, seed_code):
        self.send_base_key = send_key
        self.recv_base_key = recv_key
        self.seed_code = seed_code
        self.send_seq = 1
        self.recv_seq = 1
        self.send_label = b"server->client"
        self.recv_label = b"client->server"

    def _derive_key(self, base_key, seq, label):
        """使用种子码和序列号派生动态密钥"""
        info = self.seed_code + struct.pack(">Q", seq) + label
        return hkdf(base_key, info, length=32)

    def encrypt(self, pt: bytes, aad: bytes = b""):
        dynamic_key = self._derive_key(self.send_base_key, self.send_seq, self.send_label)
        aead = ChaCha20Poly1305(dynamic_key)
        n = nonce_from_seq(self.send_seq, self.send_label)
        self.send_seq += 1
        return aead.encrypt(n, pt, aad)

    def decrypt(self, ct: bytes, aad: bytes = b""):
        dynamic_key = self._derive_key(self.recv_base_key, self.recv_seq, self.recv_label)
        aead = ChaCha20Poly1305(dynamic_key)
        n = nonce_from_seq(self.recv_seq, self.recv_label)
        pt = aead.decrypt(n, ct, aad)
        self.recv_seq += 1
        return pt


def handle_conn(conn, addr, server_priv, server_cert, ca_cert):
    """处理连接，添加状态机和资源限制"""
    with COMPUTE_SEM:  # 计算资源限制
        logger.info(f"connection from {addr}")
        transcript_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        handshake_start_time = time.time()

        # 状态机初始化
        current_state = "INIT"

        try:
            conn.settimeout(HANDSHAKE_TIMEOUT)

            # ==== 状态1: 接收ClientHello ====
            logger.info(f"Step 1/13: Waiting for ClientHello from {addr}")
            ch_frame = recv_frame(conn)
            if current_state != "INIT" or not ch_frame.startswith(b"CLIENTHELLO|"):
                raise ProtocolError("Invalid state for ClientHello")
            current_state = "CLIENTHELLO_RECEIVED"

            payload = ch_frame[len(b"CLIENTHELLO|"):]
            if len(payload) != 48:
                raise ValueError("invalid ClientHello payload length")

            client_eph_pub = payload[:32]
            nonce_c = payload[32:48]

            # 检查nonce是否重复使用
            if not check_nonce_replay(nonce_c, addr):
                raise ValueError("nonce reuse detected - possible replay attack")

            transcript_hash.update(ch_frame)
            transcript = transcript_hash.copy().finalize()

            # ==== 状态2: 发送ServerHello ====
            logger.info(f"Step 2/13: Sending ServerHello to {addr}")
            if current_state != "CLIENTHELLO_RECEIVED":
                raise ProtocolError("Invalid state for ServerHello")
            current_state = "SERVERHELLO_SENT"

            server_eph = x25519.X25519PrivateKey.generate()
            server_eph_pub = server_eph.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw
            )
            nonce_s = os.urandom(16)

            # 修复：只发送公钥和nonce
            sh_payload = server_eph_pub + nonce_s
            conn.sendall(pack(b"SERVERHELLO|" + sh_payload))

            transcript_hash.update(b"SERVERHELLO|" + sh_payload)
            transcript = transcript_hash.copy().finalize()

            # ==== 状态3: 发送ServerCertSend ====
            logger.info(f"Step 3/13: Sending ServerCertSend to {addr}")
            if current_state != "SERVERHELLO_SENT":
                raise ProtocolError("Invalid state for ServerCertSend")
            current_state = "SERVERCERTSEND_SENT"

            scert = b"SERVERCERTSEND|" + server_cert.public_bytes(serialization.Encoding.PEM)
            conn.sendall(pack(scert))
            transcript_hash.update(scert)
            transcript = transcript_hash.copy().finalize()

            # ==== 状态4: 发送ClientCertRequest ====
            logger.info(f"Step 4/13: Sending ClientCertRequest to {addr}")
            if current_state != "SERVERCERTSEND_SENT":
                raise ProtocolError("Invalid state for ClientCertRequest")
            current_state = "CLIENTCERTREQUEST_SENT"

            ccr = b"CLIENTCERTREQUEST|"
            conn.sendall(pack(ccr))
            transcript_hash.update(ccr)
            transcript = transcript_hash.copy().finalize()

            # ==== 状态5: 接收ClientCertSend ====
            logger.info(f"Step 5/13: Waiting for ClientCertSend from {addr}")
            ccert_frame = recv_frame(conn)
            if current_state != "CLIENTCERTREQUEST_SENT":
                raise ProtocolError("Invalid state for ClientCertSend")
            current_state = "CLIENTCERTSEND_RECEIVED"

            client_cert_pem = parse_protocol_frame(ccert_frame, b"CLIENTCERTSEND")
            try:
                client_cert = x509.load_pem_x509_certificate(
                    client_cert_pem,
                    backend=default_backend()
                )
            except Exception as e:
                raise ValueError(f"Failed to load client certificate: {str(e)}")
            transcript_hash.update(ccert_frame)
            transcript = transcript_hash.copy().finalize()

            # ==== 状态6: 验证客户端证书 ====
            logger.info(f"Step 6/13: Verifying client certificate from {addr}")
            try:
                # 尝试用普通CA验证
                ca_pub = ca_cert.public_key()
                if not isinstance(ca_pub, ed25519.Ed25519PublicKey):
                    raise ValueError("CA public key is not Ed25519")
                ca_pub.verify(
                    client_cert.signature,
                    client_cert.tbs_certificate_bytes
                )
                logger.info(f"Client certificate verified successfully for {addr} (using regular CA)")
            except (InvalidSignature, ValueError):
                # 如果普通CA验证失败，尝试用匿名CA验证
                try:
                    anonymous_ca_cert = load_anonymous_ca_cert()
                    anon_ca_pub = anonymous_ca_cert.public_key()
                    if not isinstance(anon_ca_pub, ed25519.Ed25519PublicKey):
                        raise ValueError("Anonymous CA public key is not Ed25519")
                    anon_ca_pub.verify(
                        client_cert.signature,
                        client_cert.tbs_certificate_bytes
                    )
                    logger.info(f"Client certificate verified successfully for {addr} (using anonymous CA)")
                except (InvalidSignature, ValueError) as e:
                    raise ValueError(f"Client certificate verification failed: {str(e)}")
            except Exception as e:
                raise ValueError(f"Client certificate verification failed: {str(e)}")

            # ==== 状态7: 发送KeyExchange1 ====
            logger.info(f"Step 7/13: Sending KeyExchange1 to {addr}")
            if current_state != "CLIENTCERTSEND_RECEIVED":
                raise ProtocolError("Invalid state for KeyExchange1")
            current_state = "KEYEXCHANGE1_SENT"

            ke1_data = os.urandom(32)
            ke1 = b"KEYEXCHANGE1|" + ke1_data
            conn.sendall(pack(ke1))
            transcript_hash.update(ke1)
            transcript = transcript_hash.copy().finalize()

            # ==== 状态8: 接收KeyExchange2 ====
            logger.info(f"Step 8/13: Waiting for KeyExchange2 from {addr}")
            ke2_frame = recv_frame(conn)
            if current_state != "KEYEXCHANGE1_SENT":
                raise ProtocolError("Invalid state for KeyExchange2")
            current_state = "KEYEXCHANGE2_RECEIVED"

            ke2_data = parse_protocol_frame(ke2_frame, b"KEYEXCHANGE2")
            validate_field(ke2_data, 32, 32, "KeyExchange2 data", is_text=False)
            transcript_hash.update(ke2_frame)
            transcript = transcript_hash.copy().finalize()

            # ==== 状态9: 发送KeyConfirm1 ====
            logger.info(f"Step 9/13: Sending KeyConfirm1 to {addr}")
            if current_state != "KEYEXCHANGE2_RECEIVED":
                raise ProtocolError("Invalid state for KeyConfirm1")
            current_state = "KEYCONFIRM1_SENT"

            kc1_data = os.urandom(32)
            kc1 = b"KEYCONFIRM1|" + kc1_data
            conn.sendall(pack(kc1))
            transcript_hash.update(kc1)
            transcript = transcript_hash.copy().finalize()

            # ==== 状态10: 接收KeyConfirm2 ====
            logger.info(f"Step 10/13: Waiting for KeyConfirm2 from {addr}")
            kc2_frame = recv_frame(conn)
            if current_state != "KEYCONFIRM1_SENT":
                raise ProtocolError("Invalid state for KeyConfirm2")
            current_state = "KEYCONFIRM2_RECEIVED"

            kc2_data = parse_protocol_frame(kc2_frame, b"KEYCONFIRM2")
            validate_field(kc2_data, 32, 32, "KeyConfirm2 data", is_text=False)
            transcript_hash.update(kc2_frame)
            transcript = transcript_hash.copy().finalize()

            # ==== 状态11: 计算共享密钥 ====
            logger.info(f"Step 11/13: Calculating shared key for {addr}")
            shared = server_eph.exchange(x25519.X25519PublicKey.from_public_bytes(client_eph_pub))

            info = b"SC-HKDF|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|" + nonce_c + b"|" + nonce_s
            info += b"|" + ke1_data + b"|" + ke2_data + b"|" + kc1_data + b"|" + kc2_data

            okm = hkdf(shared, info, length=64)
            k_c2s = okm[:32]
            k_s2c = okm[32:]

            del server_eph

            # ==== 状态12: 生成并发送种子码 ====
            logger.info(f"Step 12/13: Sending SeedCode to {addr}")
            if current_state != "KEYCONFIRM2_RECEIVED":
                raise ProtocolError("Invalid state for SeedCode")
            current_state = "SEEDCODE_SENT"

            seed_nonce = os.urandom(8)
            seed_code = os.urandom(32) + secrets.token_bytes(32)  # 64字节高熵种子码

            # 修复：绑定客户端指纹
            digest = hashes.Hash(hashes.SHA256())
            digest.update(client_cert.public_bytes(serialization.Encoding.DER))
            client_fingerprint = digest.finalize()[:16]

            seed_payload = b"SEEDCODE|" + seed_nonce + seed_code + client_fingerprint
            temp_aead = ChaCha20Poly1305(k_s2c)
            temp_nonce = transcript[:12]
            encrypted_payload = temp_aead.encrypt(temp_nonce, seed_payload, transcript)
            conn.sendall(pack(encrypted_payload))
            transcript_hash.update(encrypted_payload)
            transcript = transcript_hash.copy().finalize()

            # ==== 状态13: 接收ClientAuth ====
            logger.info(f"Step 13/13: Waiting for ClientAuth from {addr}")
            caut_frame = recv_frame(conn)
            if current_state != "SEEDCODE_SENT":
                raise ProtocolError("Invalid state for ClientAuth")
            current_state = "CLIENTAUTH_RECEIVED"

            sig_client = parse_protocol_frame(caut_frame, b"CLIENTAUTH")
            client_pub = client_cert.public_key()
            if not isinstance(client_pub, ed25519.Ed25519PublicKey):
                raise ValueError("client public key is not Ed25519")

            try:
                client_pub.verify(sig_client, transcript)
                logger.info(f"Client signature verified successfully for {addr}")
            except InvalidSignature:
                raise ValueError("client signature verification failed")

            transcript_hash.update(caut_frame)
            transcript = transcript_hash.copy().finalize()

            # ==== 状态14: 发送ServerAuth ====
            sig_server = server_priv.sign(transcript)
            sa = b"SERVERAUTH|" + sig_server
            conn.sendall(pack(sa))
            transcript_hash.update(sa)
            transcript = transcript_hash.copy().finalize()
            current_state = "SERVERAUTH_SENT"

            # ==== 状态15: 发送SecureAck ====
            sess = Session(send_key=k_s2c, recv_key=k_c2s, seed_code=seed_code)
            ct = sess.encrypt(b"ACK", aad=transcript)
            conn.sendall(pack(b"SECUREACK|" + ct))
            current_state = "SECUREACK_SENT"

            handshake_time = time.time() - handshake_start_time
            logger.info(f"Handshake completed with {addr} (耗时: {handshake_time:.2f}s)")

            # 重置超时设置
            conn.settimeout(None)

            # 后续加密通信
            while True:
                try:
                    frm = recv_frame(conn)
                except ConnectionError as e:
                    safe_log_error(f"Connection error with {addr}: {str(e)}")
                    break

                # 严格帧解析器
                if not frm.startswith(b"DATA") or len(frm) < 12:
                    safe_log_error(f"Invalid frame format from {addr}")
                    break

                try:
                    seq_bytes = frm[4:12]
                    seq = struct.unpack(">Q", seq_bytes)[0]
                    ct = frm[12:]

                    # 序列号检查
                    if seq != sess.recv_seq:
                        raise SequenceError(f"Sequence number mismatch: expected {sess.recv_seq}, got {seq}")

                    pt = sess.decrypt(ct)
                    logger.info(f"Received from {addr}: {pt}")

                    # 响应处理
                    current_seq = sess.send_seq
                    header = struct.pack(">Q", current_seq)
                    resp = b"echo: " + pt
                    ct_resp = sess.encrypt(resp)
                    data_frame = b"DATA" + header + ct_resp
                    conn.sendall(pack(data_frame))

                except SequenceError as e:
                    safe_log_error(f"Sequence error from {addr}: {str(e)}")
                    break
                except Exception as e:
                    safe_log_error(f"Processing error from {addr}: {str(e)}")
                    break

        except socket.timeout:
            safe_log_error(f"Handshake timeout with {addr}")
        except Exception as e:
            safe_log_error(f"Connection error with {addr}: {type(e).__name__}: {str(e)}")
        finally:
            conn.close()


def handle_conn_wrapper(conn, addr, server_priv, server_cert, ca_cert):
    """连接处理包装器，添加连接限制"""
    with CONNECTION_SEMAPHORE:  # 连接资源限制
        handle_conn(conn, addr, server_priv, server_cert, ca_cert)


def main():
    try:
        server_priv = load_pem_priv()
        server_cert = load_pem_cert()
        ca_cert = load_ca_cert()
    except Exception as e:
        logger.error(f"Failed to load server credentials: {str(e)}")
        return

    HOST = '0.0.0.0'
    PORT = 5555
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((HOST, PORT))
        s.listen(5)
        logger.info(f"Listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            t = threading.Thread(
                target=handle_conn_wrapper,
                args=(conn, addr, server_priv, server_cert, ca_cert),
                daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
    except Exception as e:
        safe_log_error(f"Server error: {str(e)}")
    finally:
        s.close()


if __name__ == "__main__":
    main()