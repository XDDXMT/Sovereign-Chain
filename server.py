#!/usr/bin/env python3
# server.py
"""
Sovereign-Chain Server - 优化握手延迟版本
主要优化：
1. 合并 ServerHello, ServerCertSend, ClientCertRequest 为一次发送
2. 并行化密钥交换步骤
3. 优化网络往返次数
4. 保持向后兼容
"""
import random
import socket, struct, os, threading, time, logging, math, secrets
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import hashlib
import itertools
from collections import deque
import queue
import concurrent.futures

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

FRAME_HDR = 4
PROTO_VER = b"SC-EE-2"  # 协议版本升级
CIPHER_SUITE = b"X25519-Ed25519-CHACHA20POLY1305-HKDFSHA256"
HANDSHAKE_TIMEOUT = 15  # 握手超时时间减少到15秒

# 连接和计算资源限制
MAX_CONNECTIONS = 100
CONNECTION_SEMAPHORE = threading.Semaphore(MAX_CONNECTIONS)
COMPUTE_SEM = threading.Semaphore(50)

# 线程池用于并行计算
COMPUTE_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=20)

# 错误频率限制
ERROR_TIMES = deque(maxlen=100)
ERROR_LOCK = threading.Lock()

# 缓存已计算的值，减少重复计算
SHARED_KEY_CACHE = {}
CACHE_LOCK = threading.Lock()


def safe_log_error(message):
    """安全日志记录，防止日志泛洪攻击"""
    now = time.time()
    with ERROR_LOCK:
        ERROR_TIMES.append(now)
        recent_errors = [t for t in ERROR_TIMES if now - t < 10]
        if len(recent_errors) > 50:
            return
        logger.error(message)


# 用于防止重放攻击的nonce缓存
nonce_cache = {}
nonce_cache_lock = threading.Lock()
NONCE_CACHE_MAX_SIZE = 10000
NONCE_CACHE_EXPIRE = 300


class ProtocolError(Exception):
    pass


class SequenceError(Exception):
    pass


def pack(buf: bytes) -> bytes:
    return struct.pack(">I", len(buf)) + buf


def recv_exact(sock, n):
    buf = b""
    start_time = time.time()
    while len(buf) < n:
        try:
            remaining_time = HANDSHAKE_TIMEOUT - (time.time() - start_time)
            if remaining_time <= 0:
                raise socket.timeout("receive timeout")
            sock.settimeout(min(1.0, remaining_time))  # 使用动态超时
            r = sock.recv(min(4096, n - len(buf)))
            if not r:
                raise ConnectionError("peer closed")
            buf += r
        except socket.timeout:
            if time.time() - start_time >= HANDSHAKE_TIMEOUT:
                raise ConnectionError("receive timeout")
        except ConnectionResetError:
            raise ConnectionError("connection reset by peer")
    sock.settimeout(HANDSHAKE_TIMEOUT)
    return buf


def recv_frame(sock):
    try:
        hdr = recv_exact(sock, FRAME_HDR)
        (l,) = struct.unpack(">I", hdr)
        if l > 1_000_000:
            raise ValueError("frame too large")
        return recv_exact(sock, l)
    except Exception as e:
        raise ConnectionError(f"failed to receive frame: {str(e)}")


def send_frame(sock, data: bytes):
    """发送帧，带有超时控制"""
    try:
        sock.sendall(pack(data))
    except Exception as e:
        raise ConnectionError(f"failed to send frame: {str(e)}")


def load_pem_priv():
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
    try:
        with open("server_cert.pem", "rb") as f:
            return x509.load_pem_x509_certificate(
                f.read(),
                backend=default_backend()
            )
    except Exception as e:
        raise ValueError(f"failed to load certificate: {str(e)}")


def load_ca_cert():
    try:
        with open("ca_cert.pem", "rb") as f:
            return x509.load_pem_x509_certificate(
                f.read(),
                backend=default_backend()
            )
    except Exception as e:
        raise ValueError(f"failed to load CA certificate: {str(e)}")


def load_anonymous_ca_cert():
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


def compute_shared_key_async(server_eph, client_eph_pub_bytes, cache_key):
    """异步计算共享密钥"""
    try:
        client_eph_pub = x25519.X25519PublicKey.from_public_bytes(client_eph_pub_bytes)
        shared = server_eph.exchange(client_eph_pub)

        with CACHE_LOCK:
            SHARED_KEY_CACHE[cache_key] = shared
        return shared
    except Exception as e:
        logger.error(f"Failed to compute shared key: {str(e)}")
        return None


def nonce_from_seq(seq: int, label: bytes):
    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    h.update(label)
    prefix = h.finalize()[:4]
    return prefix + struct.pack(">Q", seq)


def check_nonce_replay(nonce, addr):
    current_time = time.time()
    with nonce_cache_lock:
        for key, (timestamp, _) in list(nonce_cache.items()):
            if current_time - timestamp > NONCE_CACHE_EXPIRE:
                del nonce_cache[key]

        if len(nonce_cache) > NONCE_CACHE_MAX_SIZE:
            items = sorted(nonce_cache.items(), key=lambda x: x[1][0])
            for key in items[:len(items) // 10]:
                del nonce_cache[key]

        if nonce in nonce_cache:
            return False

        nonce_cache[nonce] = (current_time, addr)
        return True


def validate_field(data, min_len, max_len, field_name, is_text=False):
    if not isinstance(data, bytes):
        raise ValueError(f"{field_name} must be bytes")
    if len(data) < min_len or len(data) > max_len:
        raise ValueError(f"Invalid {field_name} length: {len(data)}")

    if is_text:
        if any(b < 0x20 or b > 0x7E for b in data):
            raise ValueError(f"Invalid characters in {field_name}")


def parse_protocol_frame(frame, expected_type):
    expected_prefix = expected_type + b"|"
    if not frame.startswith(expected_prefix):
        raise ProtocolError(f"Invalid frame format for {expected_type.decode()}")
    return frame[len(expected_prefix):]


def send_combined_message(conn, messages):
    """合并发送多个消息，减少网络往返"""
    combined = b""
    for msg in messages:
        combined += pack(msg)
    conn.sendall(combined)


class Session:
    def __init__(self, send_key, recv_key, seed_code, role="client"):
        self.send_base_key = send_key
        self.recv_base_key = recv_key
        self.seed_code = seed_code
        self.send_seq = 1
        self.recv_seq = 1

        if role == "client":
            self.send_label = b"client->server"
            self.recv_label = b"server->client"
        else:
            self.send_label = b"server->client"
            self.recv_label = b"client->server"

    def _derive_key(self, base_key, seq, label):
        info = self.seed_code + struct.pack(">Q", seq) + label
        return hkdf(base_key, info, length=32)

    def encrypt(self, pt: bytes, aad: bytes = b""):
        dynamic_key = self._derive_key(self.send_base_key, self.send_seq, self.send_label)
        aead = ChaCha20Poly1305(dynamic_key)
        n = nonce_from_seq(self.send_seq, self.send_label)
        ct = aead.encrypt(n, pt, aad)
        self.send_seq += 1
        return ct

    def decrypt(self, ct: bytes, aad: bytes = b""):
        dynamic_key = self._derive_key(self.recv_base_key, self.recv_seq, self.recv_label)
        aead = ChaCha20Poly1305(dynamic_key)
        n = nonce_from_seq(self.recv_seq, self.recv_label)
        pt = aead.decrypt(n, ct, aad)
        self.recv_seq += 1
        return pt


def verify_client_certificate_async(client_cert_pem_bytes, ca_cert, transcript_hash, addr):
    """异步验证客户端证书"""
    try:
        client_cert = x509.load_pem_x509_certificate(
            client_cert_pem_bytes,
            backend=default_backend()
        )

        # 尝试用普通CA验证
        try:
            ca_pub = ca_cert.public_key()
            if not isinstance(ca_pub, ed25519.Ed25519PublicKey):
                raise ValueError("CA public key is not Ed25519")
            ca_pub.verify(
                client_cert.signature,
                client_cert.tbs_certificate_bytes
            )
            return client_cert, "regular"
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
                return client_cert, "anonymous"
            except (InvalidSignature, ValueError) as e:
                raise ValueError(f"Client certificate verification failed: {str(e)}")
    except Exception as e:
        return None, str(e)


def handle_conn(conn, addr, server_priv, server_cert, ca_cert):
    with COMPUTE_SEM:
        logger.info(f"connection from {addr}")
        transcript_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        handshake_start_time = time.time()
        futures = []

        try:
            conn.settimeout(HANDSHAKE_TIMEOUT)

            # ==== 步骤1: 接收ClientHello ====
            logger.info(f"Step 1/7: Waiting for ClientHello from {addr}")
            ch_frame = recv_frame(conn)
            if not ch_frame.startswith(b"CLIENTHELLO|"):
                raise ProtocolError("Invalid ClientHello format")

            payload = ch_frame[len(b"CLIENTHELLO|"):]
            if len(payload) != 48:
                raise ValueError("invalid ClientHello payload length")

            client_eph_pub = payload[:32]
            nonce_c = payload[32:48]

            if not check_nonce_replay(nonce_c, addr):
                raise ValueError("nonce reuse detected")

            transcript_hash.update(ch_frame)
            transcript = transcript_hash.copy().finalize()

            # ==== 步骤2: 发送合并的消息 (ServerHello + ServerCertSend + ClientCertRequest) ====
            logger.info(f"Step 2/7: Sending combined messages to {addr}")

            # 生成临时的密钥交换材料
            server_eph = x25519.X25519PrivateKey.generate()
            server_eph_pub = server_eph.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw
            )
            nonce_s = os.urandom(16)

            # 预计算可能的密钥交换和确认数据
            ke1_data = os.urandom(32)
            ke2_data = os.urandom(32)
            kc1_data = os.urandom(32)
            kc2_data = os.urandom(32)

            # 准备合并的消息
            server_hello = b"SERVERHELLO|" + server_eph_pub + nonce_s
            server_cert_msg = b"SERVERCERTSEND|" + server_cert.public_bytes(serialization.Encoding.PEM)
            client_cert_request = b"CLIENTCERTREQUEST|"

            # 合并发送，减少往返
            send_combined_message(conn, [server_hello, server_cert_msg, client_cert_request])

            transcript_hash.update(server_hello)
            transcript_hash.update(server_cert_msg)
            transcript_hash.update(client_cert_request)
            transcript = transcript_hash.copy().finalize()

            # 启动异步密钥计算
            cache_key = (addr, nonce_c.tobytes() if hasattr(nonce_c, 'tobytes') else nonce_c)
            future = COMPUTE_POOL.submit(
                compute_shared_key_async,
                server_eph,
                client_eph_pub,
                cache_key
            )
            futures.append(("shared_key", future))

            # ==== 步骤3: 接收ClientCertSend并异步验证 ====
            logger.info(f"Step 3/7: Waiting for ClientCertSend from {addr}")
            ccert_frame = recv_frame(conn)
            client_cert_pem = parse_protocol_frame(ccert_frame, b"CLIENTCERTSEND")

            # 异步验证证书
            cert_future = COMPUTE_POOL.submit(
                verify_client_certificate_async,
                client_cert_pem,
                ca_cert,
                transcript_hash.copy(),
                addr
            )
            futures.append(("cert_verify", cert_future))

            transcript_hash.update(ccert_frame)
            transcript = transcript_hash.copy().finalize()

            # ==== 步骤4: 发送预计算的密钥材料和种子码 ====
            logger.info(f"Step 4/7: Sending precomputed key materials and seed code to {addr}")

            # 等待共享密钥计算完成
            shared_key_future = futures[0][1]
            shared = shared_key_future.result(timeout=5)
            if shared is None:
                raise ProtocolError("Failed to compute shared key")

            # 生成种子码
            seed_nonce = os.urandom(8)
            seed_code = os.urandom(32) + secrets.token_bytes(32)
            order_seed = os.urandom(32)

            # 使用临时密钥加密种子码
            info = b"SC-HKDF|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|" + nonce_c + b"|" + nonce_s
            temp_key = hkdf(shared, info, length=64)
            k_s2c = temp_key[32:]

            # 生成并发送所有密钥交换和确认数据
            seed_payload = b"SEEDCODE|" + seed_nonce + seed_code + order_seed

            temp_aead = ChaCha20Poly1305(k_s2c)
            temp_nonce = transcript[:12]
            encrypted_seed = temp_aead.encrypt(temp_nonce, seed_payload, transcript)

            # 生成所有密钥交换和确认消息
            ke1 = b"KEYEXCHANGE1|" + ke1_data
            ke2 = b"KEYEXCHANGE2|" + ke2_data
            kc1 = b"KEYCONFIRM1|" + kc1_data
            kc2 = b"KEYCONFIRM2|" + kc2_data

            # 合并发送
            send_combined_message(conn, [encrypted_seed, ke1, ke2, kc1, kc2])

            # 更新transcript
            transcript_hash.update(encrypted_seed)
            transcript_hash.update(ke1)
            transcript_hash.update(ke2)
            transcript_hash.update(kc1)
            transcript_hash.update(kc2)
            transcript = transcript_hash.copy().finalize()

            # ==== 步骤5: 接收ClientAuth ====
            logger.info(f"Step 5/7: Waiting for ClientAuth from {addr}")

            # 等待证书验证完成
            cert_result, cert_type = cert_future.result(timeout=5)
            if cert_result is None:
                raise ProtocolError(f"Certificate verification failed: {cert_type}")

            client_cert = cert_result
            logger.info(f"Client certificate verified successfully for {addr} (using {cert_type} CA)")

            caut_frame = recv_frame(conn)
            sig_client = parse_protocol_frame(caut_frame, b"CLIENTAUTH")
            client_pub = client_cert.public_key()

            if not isinstance(client_pub, ed25519.Ed25519PublicKey):
                raise ValueError("client public key is not Ed25519")

            client_pub.verify(sig_client, transcript)
            logger.info(f"Client signature verified successfully for {addr}")

            transcript_hash.update(caut_frame)
            transcript = transcript_hash.copy().finalize()

            # ==== 步骤6: 发送ServerAuth ====
            logger.info(f"Step 6/7: Sending ServerAuth to {addr}")
            sig_server = server_priv.sign(transcript)
            sa = b"SERVERAUTH|" + sig_server
            send_frame(conn, sa)
            transcript_hash.update(sa)
            transcript = transcript_hash.copy().finalize()

            # ==== 步骤7: 创建会话并发送SecureAck ====
            logger.info(f"Step 7/7: Establishing secure session with {addr}")

            # 派生最终会话密钥
            info = b"SC-HKDF|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|" + nonce_c + b"|" + nonce_s
            info += b"|" + ke1_data + b"|" + ke2_data
            info += b"|" + kc1_data + b"|" + kc2_data
            okm = hkdf(shared, info, length=64)
            k_c2s = okm[:32]
            k_s2c = okm[32:]

            sess = Session(send_key=k_s2c, recv_key=k_c2s, seed_code=seed_code, role="server")
            ct = sess.encrypt(b"ACK", aad=transcript)
            send_frame(conn, b"SECUREACK|" + ct)

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

                if not frm.startswith(b"DATA") or len(frm) < 12:
                    safe_log_error(f"Invalid frame format from {addr}")
                    break

                try:
                    seq_bytes = frm[4:12]
                    seq = struct.unpack(">Q", seq_bytes)[0]
                    ct = frm[12:]

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
                    send_frame(conn, data_frame)

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
            # 清理未完成的异步任务
            for name, future in futures:
                if not future.done():
                    future.cancel()
            conn.close()


def handle_conn_wrapper(conn, addr, server_priv, server_cert, ca_cert):
    with CONNECTION_SEMAPHORE:
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
        COMPUTE_POOL.shutdown(wait=True)
    except Exception as e:
        safe_log_error(f"Server error: {str(e)}")
    finally:
        s.close()


if __name__ == "__main__":
    main()