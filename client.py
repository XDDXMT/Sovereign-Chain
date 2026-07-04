#!/usr/bin/env python3
# client.py
"""
Sovereign-Chain Client - 优化握手延迟版本
"""
import random
import socket, struct, os, time, logging, math, secrets, hashlib, traceback
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import threading
from collections import deque
import datetime
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import concurrent.futures
from security import (
    CIPHER_SUITE,
    PROTO_VER,
    Session,
    hkdf,
    validate_peer_certificate,
    verify_private_key_matches_certificate,
)

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

FRAME_HDR = 4
HANDSHAKE_TIMEOUT = 15  # 握手超时时间减少到15秒
CLIENT_HELLO_PREFIX = b"CLIENTHELLO|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|"
SERVER_HELLO_PREFIX = b"SERVERHELLO|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|"

# 错误频率限制
ERROR_TIMES = deque(maxlen=100)
ERROR_LOCK = threading.Lock()

# 线程池
COMPUTE_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=10)


def safe_log_error(message):
    now = time.time()
    with ERROR_LOCK:
        ERROR_TIMES.append(now)
        recent_errors = [t for t in ERROR_TIMES if now - t < 10]
        if len(recent_errors) > 50:
            return
        logger.error(message)


def pack(b):
    return struct.pack(">I", len(b)) + b


def recv_exact(sock, n):
    buf = b""
    start_time = time.time()
    while len(buf) < n:
        try:
            remaining_time = HANDSHAKE_TIMEOUT - (time.time() - start_time)
            if remaining_time <= 0:
                raise socket.timeout("receive timeout")
            sock.settimeout(min(1.0, remaining_time))
            r = sock.recv(min(4096, n - len(buf)))
            if not r:
                raise ConnectionError("Connection closed by peer")
            buf += r
        except socket.timeout:
            if time.time() - start_time >= HANDSHAKE_TIMEOUT:
                raise ConnectionError("Receive timeout")
        except ConnectionResetError:
            raise ConnectionError("Connection reset by peer")
    sock.settimeout(HANDSHAKE_TIMEOUT)
    return buf


def recv_frame(sock):
    try:
        hdr = recv_exact(sock, FRAME_HDR)
        (l,) = struct.unpack(">I", hdr)
        if l > 1_000_000:
            raise ValueError("Frame too large")
        return recv_exact(sock, l)
    except Exception as e:
        raise ConnectionError(f"Failed to receive frame: {str(e)}")


def send_frame(sock, data: bytes):
    try:
        sock.sendall(pack(data))
    except Exception as e:
        raise ConnectionError(f"Failed to send frame: {str(e)}")


def send_combined_message(sock, messages):
    """合并发送多个消息"""
    combined = b""
    for msg in messages:
        combined += pack(msg)
    sock.sendall(combined)


def load_priv():
    try:
        password = os.getenv("SC_CLIENT_KEY_PASSWORD")
        with open(os.getenv("SC_CLIENT_KEY_FILE", "client_key.pem"), "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=password.encode() if password else None,
                backend=default_backend()
            )
    except FileNotFoundError:
        return None
    except Exception as e:
        raise ValueError(f"Failed to load private key: {str(e)}")


def load_cert():
    try:
        with open(os.getenv("SC_CLIENT_CERT_FILE", "client_cert.pem"), "rb") as f:
            return x509.load_pem_x509_certificate(
                f.read(),
                backend=default_backend()
            )
    except FileNotFoundError:
        return None
    except Exception as e:
        raise ValueError(f"Failed to load certificate: {str(e)}")


def load_ca_cert():
    try:
        with open(os.getenv("SC_CA_CERT_FILE", "ca_cert.pem"), "rb") as f:
            return x509.load_pem_x509_certificate(
                f.read(),
                backend=default_backend()
            )
    except Exception as e:
        raise ValueError(f"Failed to load CA certificate: {str(e)}")


def generate_temp_cert():
    logger.info("Generating temporary certificate for anonymous connection")

    try:
        with open(os.getenv("SC_ANONYMOUS_CA_CERT_FILE", "anonymous_ca_cert.pem"), "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        password = os.getenv("SC_ANONYMOUS_CA_KEY_PASSWORD")
        with open(os.getenv("SC_ANONYMOUS_CA_KEY_FILE", "anonymous_ca_key.pem"), "rb") as f:
            ca_priv = serialization.load_pem_private_key(
                f.read(),
                password.encode() if password else None,
                default_backend(),
            )
    except Exception as e:
        raise ValueError(f"Failed to load anonymous CA: {str(e)}")

    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"Anonymous-{secrets.token_hex(8)}"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sovereign Chain"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "SC")
    ])

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(pub_key)
    builder = builder.serial_number(x509.random_serial_number())

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + datetime.timedelta(minutes=30))

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
        critical=False,
    )

    if isinstance(ca_priv, ed25519.Ed25519PrivateKey):
        cert = builder.sign(ca_priv, algorithm=None)
    else:
        cert = builder.sign(ca_priv, algorithm=hashes.SHA256())

    return priv_key, cert


def compute_shared_key_async(client_eph, server_eph_pub_bytes):
    """异步计算共享密钥"""
    try:
        server_eph_pub = x25519.X25519PublicKey.from_public_bytes(server_eph_pub_bytes)
        shared = client_eph.exchange(server_eph_pub)
        return shared
    except Exception as e:
        logger.error(f"Failed to compute shared key: {str(e)}")
        return None


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


class ProtocolError(Exception):
    pass


def verify_server_certificate_async(server_cert_pem_bytes, ca_cert, expected_identity):
    """异步验证服务器证书"""
    try:
        server_cert = x509.load_pem_x509_certificate(
            server_cert_pem_bytes,
            backend=default_backend()
        )

        validate_peer_certificate(
            server_cert,
            ca_cert,
            role="server",
            expected_identity=expected_identity,
        )
        return server_cert, True
    except Exception as e:
        return None, str(e)


def client_handshake(host="127.0.0.1", port=5555, expected_server_name=None):
    logger.info(f"Starting optimized handshake with {host}:{port}")
    expected_server_name = expected_server_name or os.getenv(
        "SC_SERVER_NAME", "Sovereign-Chain-Server"
    )

    # 加载证书
    try:
        client_priv = load_priv()
        client_cert = load_cert()
        ca_cert = load_ca_cert()

        if client_priv is None or client_cert is None:
            if os.getenv("SC_ALLOW_ANONYMOUS_CLIENTS") != "1":
                raise ValueError("client certificate is required; anonymous mode is disabled")
            logger.warning("Anonymous client mode is enabled")
            client_priv, client_cert = generate_temp_cert()
        verify_private_key_matches_certificate(client_priv, client_cert)
    except Exception as e:
        raise ConnectionError(f"Failed to load credentials: {str(e)}")

    # 连接服务器
    try:
        s = socket.create_connection((host, port))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        s.settimeout(HANDSHAKE_TIMEOUT)
    except Exception as e:
        raise ConnectionError(f"Failed to connect to server: {str(e)}")

    handshake_start_time = time.time()
    transcript_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    futures = []

    try:
        # ==== 步骤1: 发送ClientHello ====
        logger.info("Step 1/7: Sending ClientHello")

        client_eph = x25519.X25519PrivateKey.generate()
        client_eph_pub = client_eph.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
        nonce_c = os.urandom(16)

        ch = CLIENT_HELLO_PREFIX + client_eph_pub + nonce_c
        send_frame(s, ch)
        transcript_hash.update(ch)
        transcript = transcript_hash.copy().finalize()

        # ==== 步骤2: 接收合并的消息 (ServerHello, ServerCertSend, ClientCertRequest) ====
        logger.info("Step 2/7: Receiving combined server messages")

        # 接收三个合并的消息
        sh_frame = recv_frame(s)
        scert_frame = recv_frame(s)
        ccr_frame = recv_frame(s)

        # 解析ServerHello
        if not sh_frame.startswith(SERVER_HELLO_PREFIX):
            raise ValueError("Invalid ServerHello message format")

        sh_payload = sh_frame[len(SERVER_HELLO_PREFIX):]
        if len(sh_payload) != 48:
            raise ValueError(f"Invalid ServerHello payload length: {len(sh_payload)}")

        server_eph_pub = sh_payload[:32]
        nonce_s = sh_payload[32:48]

        transcript_hash.update(sh_frame)
        transcript = transcript_hash.copy().finalize()

        # 异步启动共享密钥计算
        shared_key_future = COMPUTE_POOL.submit(
            compute_shared_key_async,
            client_eph,
            server_eph_pub,
        )
        futures.append(("shared_key", shared_key_future))

        # 解析ServerCertSend
        server_cert_pem = parse_protocol_frame(scert_frame, b"SERVERCERTSEND")

        # 异步验证服务器证书
        cert_future = COMPUTE_POOL.submit(
            verify_server_certificate_async,
            server_cert_pem,
            ca_cert,
            expected_server_name,
        )
        futures.append(("cert_verify", cert_future))

        transcript_hash.update(scert_frame)
        transcript = transcript_hash.copy().finalize()

        # 解析ClientCertRequest
        parse_protocol_frame(ccr_frame, b"CLIENTCERTREQUEST")
        transcript_hash.update(ccr_frame)
        transcript = transcript_hash.copy().finalize()

        # ==== 步骤3: 发送ClientCertSend ====
        logger.info("Step 3/7: Sending ClientCertSend")

        ccert_fr = b"CLIENTCERTSEND|" + client_cert.public_bytes(serialization.Encoding.PEM)
        send_frame(s, ccert_fr)
        transcript_hash.update(ccert_fr)
        transcript = transcript_hash.copy().finalize()

        # ==== 步骤4: 接收种子码和预计算的密钥材料 ====
        logger.info("Step 4/7: Receiving seed code and precomputed key materials")

        # 接收多个合并的消息
        seed_frame = recv_frame(s)
        ke1_frame = recv_frame(s)
        ke2_frame = recv_frame(s)
        kc1_frame = recv_frame(s)
        kc2_frame = recv_frame(s)

        # 等待共享密钥计算完成
        shared = shared_key_future.result(timeout=5)
        if shared is None:
            raise ProtocolError("Failed to compute shared key")

        # 等待证书验证完成
        server_cert, cert_result = cert_future.result(timeout=5)
        if server_cert is None:
            raise ProtocolError(f"Server certificate verification failed: {cert_result}")

        logger.info("Server certificate verified successfully")

        # 解密种子码
        info = b"SC-HKDF|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|" + nonce_c + b"|" + nonce_s
        temp_key = hkdf(shared, info, length=64)
        k_s2c = temp_key[32:]

        temp_aead = ChaCha20Poly1305(k_s2c)
        temp_nonce = transcript[:12]

        try:
            seed_payload = temp_aead.decrypt(temp_nonce, seed_frame, transcript)
            if not seed_payload.startswith(b"SEEDCODE|"):
                raise ValueError("Invalid seed code format")

            seed_data = seed_payload.split(b"|", 1)[1]
            if len(seed_data) < 8:
                raise ValueError("Invalid seed data length")

            # 幂等性检查
            seed_nonce = seed_data[:8]
            if not hasattr(client_handshake, "nonce_cache"):
                client_handshake.nonce_cache = set()

            if seed_nonce in client_handshake.nonce_cache:
                raise ValueError("Seed frame replay detected")
            client_handshake.nonce_cache.add(seed_nonce)

        except Exception as e:
            logger.error(f"Seed frame processing failed: {str(e)}")
            s.close()
            raise

        # 解析预计算的密钥材料
        ke1_data = parse_protocol_frame(ke1_frame, b"KEYEXCHANGE1")
        ke2_data = parse_protocol_frame(ke2_frame, b"KEYEXCHANGE2")
        kc1_data = parse_protocol_frame(kc1_frame, b"KEYCONFIRM1")
        kc2_data = parse_protocol_frame(kc2_frame, b"KEYCONFIRM2")

        validate_field(ke1_data, 32, 32, "KeyExchange1 data")
        validate_field(ke2_data, 32, 32, "KeyExchange2 data")
        validate_field(kc1_data, 32, 32, "KeyConfirm1 data")
        validate_field(kc2_data, 32, 32, "KeyConfirm2 data")

        # 更新transcript
        transcript_hash.update(seed_frame)
        transcript_hash.update(ke1_frame)
        transcript_hash.update(ke2_frame)
        transcript_hash.update(kc1_frame)
        transcript_hash.update(kc2_frame)
        transcript = transcript_hash.copy().finalize()

        # ==== 步骤5: 发送ClientAuth ====
        logger.info("Step 5/7: Sending ClientAuth")

        sig_client = client_priv.sign(transcript)
        auth_msg = b"CLIENTAUTH|" + sig_client
        send_frame(s, auth_msg)
        transcript_hash.update(auth_msg)
        transcript = transcript_hash.copy().finalize()

        # ==== 步骤6: 接收ServerAuth ====
        logger.info("Step 6/7: Receiving ServerAuth")

        sa_frame = recv_frame(s)
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

        # ==== 步骤7: 接收SecureAck并建立会话 ====
        logger.info("Step 7/7: Establishing secure session")

        ack_frame = recv_frame(s)

        # 派生最终会话密钥
        info = b"SC-HKDF|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|" + nonce_c + b"|" + nonce_s
        info += b"|" + ke1_data + b"|" + ke2_data
        info += b"|" + kc1_data + b"|" + kc2_data
        okm = hkdf(shared, info, length=64)
        k_c2s = okm[:32]
        k_s2c = okm[32:]

        sess = Session(
            send_key=k_c2s,
            recv_key=k_s2c,
            seed_code=seed_data[8:72] if len(seed_data) >= 72 else seed_data[8:],
            role="client",
            session_id=transcript,
            cipher_suite=CIPHER_SUITE,
        )

        ct = parse_protocol_frame(ack_frame, b"SECUREACK")
        try:
            ack = sess.decrypt(
                ct, aad=transcript, frame_type=b"SECUREACK"
            )
            if ack != b"ACK":
                raise ValueError("Invalid ACK value")
            logger.info("Secure ACK verified successfully")
        except Exception as e:
            raise ValueError(f"Secure ACK verification failed: {str(e)}")

        transcript_hash.update(ack_frame)
        transcript = transcript_hash.copy().finalize()

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
    finally:
        # 清理未完成的异步任务
        for name, future in futures:
            if not future.done():
                future.cancel()


def main():
    try:
        sess, s = client_handshake("127.0.0.1", 5555)
        logger.info("Starting secure communication")
        try:
            while True:
                line = input("msg> ")
                if not line:
                    continue

                current_seq, ct = sess.encrypt_with_sequence(line.encode())
                header = struct.pack(">Q", current_seq)
                data_frame = b"DATA" + header + ct
                send_frame(s, data_frame)

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
                    resp = sess.decrypt_with_sequence(resp_seq, resp_ct)
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
