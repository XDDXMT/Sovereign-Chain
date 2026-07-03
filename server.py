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
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import hashlib
import itertools
from collections import deque
import queue
import concurrent.futures
from security import (
    CIPHER_SUITE,
    PROTO_VER,
    Session,
    hkdf,
    validate_ca_certificate,
    validate_peer_certificate,
    verify_private_key_matches_certificate,
)

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

FRAME_HDR = 4
HANDSHAKE_TIMEOUT = 15  # 握手超时时间减少到15秒
CLIENT_HELLO_PREFIX = b"CLIENTHELLO|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|"
SERVER_HELLO_PREFIX = b"SERVERHELLO|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|"

# 连接和计算资源限制
MAX_CONNECTIONS = 100
CONNECTION_SEMAPHORE = threading.Semaphore(MAX_CONNECTIONS)
COMPUTE_SEM = threading.Semaphore(50)

# 线程池用于并行计算
COMPUTE_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=20)

# 错误频率限制
ERROR_TIMES = deque(maxlen=100)
ERROR_LOCK = threading.Lock()

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
        password = os.getenv("SC_SERVER_KEY_PASSWORD")
        with open(os.getenv("SC_SERVER_KEY_FILE", "server_key.pem"), "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=password.encode() if password else None,
                backend=default_backend()
            )
    except Exception as e:
        raise ValueError(f"failed to load private key: {str(e)}")


def load_pem_cert():
    try:
        with open(os.getenv("SC_SERVER_CERT_FILE", "server_cert.pem"), "rb") as f:
            return x509.load_pem_x509_certificate(
                f.read(),
                backend=default_backend()
            )
    except Exception as e:
        raise ValueError(f"failed to load certificate: {str(e)}")


def load_ca_cert():
    try:
        with open(os.getenv("SC_CA_CERT_FILE", "ca_cert.pem"), "rb") as f:
            return x509.load_pem_x509_certificate(
                f.read(),
                backend=default_backend()
            )
    except Exception as e:
        raise ValueError(f"failed to load CA certificate: {str(e)}")


def load_anonymous_ca_cert():
    try:
        path = os.getenv("SC_ANONYMOUS_CA_CERT_FILE", "anonymous_ca_cert.pem")
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(
                f.read(),
                backend=default_backend()
            )
    except Exception as e:
        raise ValueError(f"failed to load anonymous CA certificate: {str(e)}")


def compute_shared_key_async(server_eph, client_eph_pub_bytes):
    """异步计算共享密钥"""
    try:
        client_eph_pub = x25519.X25519PublicKey.from_public_bytes(client_eph_pub_bytes)
        return server_eph.exchange(client_eph_pub)
    except Exception as e:
        logger.error(f"Failed to compute shared key: {str(e)}")
        return None


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


def verify_client_certificate_async(client_cert_pem_bytes, ca_cert, transcript_hash, addr):
    """异步验证客户端证书"""
    try:
        client_cert = x509.load_pem_x509_certificate(
            client_cert_pem_bytes,
            backend=default_backend()
        )

        allowed_names = [
            name.strip()
            for name in os.getenv("SC_ALLOWED_CLIENT_NAMES", "Sovereign-Chain-Client").split(",")
            if name.strip()
        ]

        # First require a regular, explicitly authorized client identity.
        try:
            errors = []
            for expected_name in allowed_names:
                try:
                    validate_peer_certificate(
                        client_cert,
                        ca_cert,
                        role="client",
                        expected_identity=expected_name,
                    )
                    return client_cert, "regular"
                except ValueError as exc:
                    errors.append(str(exc))
            raise ValueError("; ".join(errors) or "no authorized client identities configured")
        except ValueError as regular_error:
            if os.getenv("SC_ALLOW_ANONYMOUS_CLIENTS") != "1":
                raise ValueError(f"Client certificate verification failed: {regular_error}")

            # Anonymous authentication is an explicit compatibility mode.
            try:
                anonymous_ca_cert = load_anonymous_ca_cert()
                validate_ca_certificate(anonymous_ca_cert, issuer_cert=ca_cert)
                validate_peer_certificate(
                    client_cert,
                    anonymous_ca_cert,
                    role="client",
                )
                return client_cert, "anonymous"
            except ValueError as e:
                raise ValueError(f"Client certificate verification failed: {str(e)}")
    except Exception as e:
        return None, str(e)


def server_handshake(conn, addr, server_priv, server_cert, ca_cert):
    """Perform the single supported SC-EE-2 handshake and return a session."""
    transcript_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    handshake_start_time = time.time()
    futures = []

    try:
        conn.settimeout(HANDSHAKE_TIMEOUT)

        logger.info(f"Step 1/7: Waiting for ClientHello from {addr}")
        ch_frame = recv_frame(conn)
        if not ch_frame.startswith(CLIENT_HELLO_PREFIX):
            raise ProtocolError("unsupported protocol version or cipher suite")
        payload = ch_frame[len(CLIENT_HELLO_PREFIX):]
        if len(payload) != 48:
            raise ValueError("invalid ClientHello payload length")
        client_eph_pub = payload[:32]
        nonce_c = payload[32:]
        if not check_nonce_replay(nonce_c, addr):
            raise ValueError("nonce reuse detected")
        transcript_hash.update(ch_frame)

        logger.info(f"Step 2/7: Sending combined messages to {addr}")
        server_eph = x25519.X25519PrivateKey.generate()
        server_eph_pub = server_eph.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        nonce_s = os.urandom(16)
        ke1_data = os.urandom(32)
        ke2_data = os.urandom(32)
        kc1_data = os.urandom(32)
        kc2_data = os.urandom(32)

        server_hello = SERVER_HELLO_PREFIX + server_eph_pub + nonce_s
        server_cert_msg = b"SERVERCERTSEND|" + server_cert.public_bytes(serialization.Encoding.PEM)
        client_cert_request = b"CLIENTCERTREQUEST|"
        send_combined_message(conn, [server_hello, server_cert_msg, client_cert_request])
        for message in (server_hello, server_cert_msg, client_cert_request):
            transcript_hash.update(message)

        shared_future = COMPUTE_POOL.submit(
            compute_shared_key_async,
            server_eph,
            client_eph_pub,
        )
        futures.append(("shared_key", shared_future))

        logger.info(f"Step 3/7: Waiting for ClientCertSend from {addr}")
        ccert_frame = recv_frame(conn)
        client_cert_pem = parse_protocol_frame(ccert_frame, b"CLIENTCERTSEND")
        cert_future = COMPUTE_POOL.submit(
            verify_client_certificate_async,
            client_cert_pem,
            ca_cert,
            transcript_hash.copy(),
            addr,
        )
        futures.append(("cert_verify", cert_future))
        transcript_hash.update(ccert_frame)
        transcript = transcript_hash.copy().finalize()

        logger.info(f"Step 4/7: Sending key materials and seed code to {addr}")
        shared = shared_future.result(timeout=5)
        if shared is None:
            raise ProtocolError("failed to compute shared key")
        seed_nonce = os.urandom(8)
        seed_code = secrets.token_bytes(64)
        order_seed = os.urandom(32)
        key_context = (
            b"SC-HKDF|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|" + nonce_c + b"|" + nonce_s
        )
        temporary_keys = hkdf(shared, key_context, length=64)
        encrypted_seed = ChaCha20Poly1305(temporary_keys[32:]).encrypt(
            transcript[:12],
            b"SEEDCODE|" + seed_nonce + seed_code + order_seed,
            transcript,
        )
        key_messages = (
            b"KEYEXCHANGE1|" + ke1_data,
            b"KEYEXCHANGE2|" + ke2_data,
            b"KEYCONFIRM1|" + kc1_data,
            b"KEYCONFIRM2|" + kc2_data,
        )
        send_combined_message(conn, [encrypted_seed, *key_messages])
        transcript_hash.update(encrypted_seed)
        for message in key_messages:
            transcript_hash.update(message)
        transcript = transcript_hash.copy().finalize()

        logger.info(f"Step 5/7: Waiting for ClientAuth from {addr}")
        client_cert, cert_type = cert_future.result(timeout=5)
        if client_cert is None:
            raise ProtocolError(f"certificate verification failed: {cert_type}")
        caut_frame = recv_frame(conn)
        sig_client = parse_protocol_frame(caut_frame, b"CLIENTAUTH")
        client_public_key = client_cert.public_key()
        if not isinstance(client_public_key, ed25519.Ed25519PublicKey):
            raise ValueError("client authentication key is not Ed25519")
        client_public_key.verify(sig_client, transcript)
        transcript_hash.update(caut_frame)
        transcript = transcript_hash.copy().finalize()

        logger.info(f"Step 6/7: Sending ServerAuth to {addr}")
        server_auth = b"SERVERAUTH|" + server_priv.sign(transcript)
        send_frame(conn, server_auth)
        transcript_hash.update(server_auth)
        transcript = transcript_hash.copy().finalize()

        logger.info(f"Step 7/7: Establishing secure session with {addr}")
        session_context = key_context
        session_context += b"|" + ke1_data + b"|" + ke2_data
        session_context += b"|" + kc1_data + b"|" + kc2_data
        session_keys = hkdf(shared, session_context, length=64)
        session = Session(
            send_key=session_keys[32:],
            recv_key=session_keys[:32],
            seed_code=seed_code,
            role="server",
        )
        ack = session.encrypt(b"ACK", aad=transcript)
        send_frame(conn, b"SECUREACK|" + ack)
        conn.settimeout(None)
        logger.info(
            f"Handshake completed with {addr} using {cert_type} authentication "
            f"(elapsed: {time.time() - handshake_start_time:.2f}s)"
        )
        return session
    finally:
        for _, future in futures:
            if not future.done():
                future.cancel()


def handle_conn(conn, addr, server_priv, server_cert, ca_cert):
    with COMPUTE_SEM:
        logger.info(f"connection from {addr}")
        try:
            session = server_handshake(conn, addr, server_priv, server_cert, ca_cert)
            while True:
                frame = recv_frame(conn)
                if not frame.startswith(b"DATA") or len(frame) < 12:
                    raise ProtocolError("invalid application frame")
                sequence = struct.unpack(">Q", frame[4:12])[0]
                plaintext = session.decrypt_with_sequence(sequence, frame[12:])
                response_sequence, response = session.encrypt_with_sequence(b"echo: " + plaintext)
                send_frame(
                    conn,
                    b"DATA" + struct.pack(">Q", response_sequence) + response,
                )
        except (ConnectionError, ProtocolError, SequenceError, ValueError) as exc:
            safe_log_error(f"Connection error with {addr}: {type(exc).__name__}: {exc}")
        except Exception as exc:
            safe_log_error(f"Unexpected connection error with {addr}: {type(exc).__name__}: {exc}")
        finally:
            conn.close()


def handle_conn_wrapper(conn, addr, server_priv, server_cert, ca_cert):
    with CONNECTION_SEMAPHORE:
        handle_conn(conn, addr, server_priv, server_cert, ca_cert)


def main():
    try:
        server_priv = load_pem_priv()
        server_cert = load_pem_cert()
        ca_cert = load_ca_cert()
        validate_peer_certificate(
            server_cert,
            ca_cert,
            role="server",
            expected_identity=os.getenv("SC_SERVER_NAME", "Sovereign-Chain-Server"),
        )
        verify_private_key_matches_certificate(server_priv, server_cert)
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
