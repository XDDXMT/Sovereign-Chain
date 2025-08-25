#!/usr/bin/env python3
# client.py
"""
Sovereign-Chain Client - 支持匿名模式
"""
import random
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
import datetime
import tempfile
from cryptography.x509.oid import NameOID

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
    """尝试加载客户端私钥，如果不存在则返回None"""
    try:
        with open("client_key.pem", "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
    except FileNotFoundError:
        return None
    except Exception as e:
        raise ValueError(f"Failed to load private key: {str(e)}")


def load_cert():
    """尝试加载客户端证书，如果不存在则返回None"""
    try:
        with open("client_cert.pem", "rb") as f:
            return x509.load_pem_x509_certificate(
                f.read(),
                backend=default_backend()
            )
    except FileNotFoundError:
        return None
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


def generate_temp_cert():
    """生成临时证书和私钥"""
    logger.info("Generating temporary certificate for anonymous connection")

    # 加载匿名CA证书和私钥
    try:
        with open("anonymous_ca_cert.pem", "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open("anonymous_ca_key.pem", "rb") as f:
            ca_priv = serialization.load_pem_private_key(f.read(), None, default_backend())
    except Exception as e:
        raise ValueError(f"Failed to load anonymous CA: {str(e)}")

    # 生成临时密钥对
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()

    # 创建证书
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

    # 修复：使用正确的UTC时间获取方式
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + datetime.timedelta(minutes=30))  # 短期有效

    # 添加基本约束
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )

    # 修复：根据私钥类型选择正确的签名算法
    if isinstance(ca_priv, ed25519.Ed25519PrivateKey):
        # Ed25519不需要指定哈希算法
        cert = builder.sign(ca_priv, algorithm=None)
    else:
        # 其他算法需要指定哈希算法
        cert = builder.sign(ca_priv, algorithm=hashes.SHA256())

    return priv_key, cert


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
    def __init__(self, send_key, recv_key, seed_code, role="client"):
        """
        初始化会话
        :param send_key: 发送密钥
        :param recv_key: 接收密钥
        :param seed_code: 种子码
        :param role: 角色 ("client" 或 "server")
        """
        self.send_base_key = send_key
        self.recv_base_key = recv_key
        self.seed_code = seed_code
        self.send_seq = 1
        self.recv_seq = 1

        # 根据角色设置标签
        if role == "client":
            self.send_label = b"client->server"
            self.recv_label = b"server->client"
        else:  # server
            self.send_label = b"server->client"
            self.recv_label = b"client->server"

    def _derive_key(self, base_key, seq, label):
        """使用种子码和序列号派生动态密钥"""
        info = self.seed_code + struct.pack(">Q", seq) + label
        return hkdf(base_key, info, length=32)

    def encrypt(self, pt: bytes, aad: bytes = b""):
        """加密数据"""
        dynamic_key = self._derive_key(self.send_base_key, self.send_seq, self.send_label)
        aead = ChaCha20Poly1305(dynamic_key)
        n = nonce_from_seq(self.send_seq, self.send_label)
        ct = aead.encrypt(n, pt, aad)
        self.send_seq += 1
        return ct

    def decrypt(self, ct: bytes, aad: bytes = b""):
        """解密数据"""
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

        # 如果没有固定证书，生成临时证书
        if client_priv is None or client_cert is None:
            logger.info("No fixed certificate found, generating temporary certificate")
            client_priv, client_cert = generate_temp_cert()
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

        # ==== 状态7: 计算共享密钥 ====
        logger.info("Step 7/13: Calculating shared key")
        shared = client_eph.exchange(x25519.X25519PublicKey.from_public_bytes(server_eph_pub))

        # ==== 状态8: 接收并解密SeedCode ====
        logger.info("Step 8/13: Receiving and decrypting SeedCode")
        encrypted_payload = recv_frame(s)
        if current_state != "CLIENTCERTSEND_SENT":
            raise ProtocolError("Invalid state for SeedCode")
        current_state = "SEEDCODE_RECEIVED"

        # 使用临时密钥解密种子码
        info = b"SC-HKDF|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|" + nonce_c + b"|" + nonce_s
        temp_key = hkdf(shared, info, length=64)
        k_s2c = temp_key[32:]  # 服务端到客户端的临时密钥

        temp_aead = ChaCha20Poly1305(k_s2c)
        temp_nonce = transcript[:12]

        try:
            payload = temp_aead.decrypt(temp_nonce, encrypted_payload, transcript)
            if not payload.startswith(b"SEEDCODE|"):
                raise ValueError("Invalid seed code format")

            seed_payload = payload.split(b"|", 1)[1]
            if len(seed_payload) < 104:  # 8+64+32+16=120 - 前缀长度
                raise ValueError("Invalid seed payload length")

            seed_nonce = seed_payload[:8]
            seed_code = seed_payload[8:72]
            order_seed = seed_payload[72:104]  # 顺序随机化种子
            client_fingerprint = seed_payload[104:120]  # 客户端指纹

            # 幂等性检查
            if seed_nonce in client_handshake.nonce_cache:
                raise ValueError("Seed frame replay detected")
            client_handshake.nonce_cache.add(seed_nonce)

            # 定义所有可能的步骤
            steps = [
                ("KEYEXCHANGE1", "recv", "KeyExchange1"),
                ("KEYEXCHANGE2", "send", "KeyExchange2"),
                ("KEYCONFIRM1", "recv", "KeyConfirm1"),
                ("KEYCONFIRM2", "send", "KeyConfirm2")
            ]

            # 使用相同的随机种子生成相同的随机顺序
            rng = random.Random(order_seed)
            step_order = list(range(len(steps)))
            rng.shuffle(step_order)

            # 记录步骤顺序
            step_names = [steps[i][0] for i in step_order]
            logger.info(f"Generated step order: {step_names}")

        except Exception as e:
            logger.error(f"Seed frame processing failed: {str(e)}")
            s.close()
            raise

        transcript_hash.update(encrypted_payload)
        transcript = transcript_hash.copy().finalize()

        # ==== 状态9-12: 根据随机顺序执行步骤 ====
        step_data = {}  # 存储各步骤生成的数据
        step_counter = 9  # 从第9步开始

        for step_idx in step_order:
            step_type, action, step_name = steps[step_idx]
            logger.info(f"Step {9 + step_idx}/13: {'Sending' if action == 'send' else 'Waiting for'} {step_name}")
            step_counter += 1

            if step_type == "KEYEXCHANGE1":
                if action == "send":
                    ke1_data = os.urandom(32)
                    step_data["KEYEXCHANGE1"] = ke1_data
                    ke1 = b"KEYEXCHANGE1|" + ke1_data
                    s.sendall(pack(ke1))
                    transcript_hash.update(ke1)
                    transcript = transcript_hash.copy().finalize()
                else:  # recv
                    ke1_frame = recv_frame(s)
                    ke1_data = parse_protocol_frame(ke1_frame, b"KEYEXCHANGE1")
                    validate_field(ke1_data, 32, 32, "KeyExchange1 data", is_text=False)
                    step_data["KEYEXCHANGE1"] = ke1_data
                    transcript_hash.update(ke1_frame)
                    transcript = transcript_hash.copy().finalize()

            elif step_type == "KEYEXCHANGE2":
                if action == "send":
                    ke2_data = os.urandom(32)
                    step_data["KEYEXCHANGE2"] = ke2_data
                    ke2 = b"KEYEXCHANGE2|" + ke2_data
                    s.sendall(pack(ke2))
                    transcript_hash.update(ke2)
                    transcript = transcript_hash.copy().finalize()
                else:  # recv
                    ke2_frame = recv_frame(s)
                    ke2_data = parse_protocol_frame(ke2_frame, b"KEYEXCHANGE2")
                    validate_field(ke2_data, 32, 32, "KeyExchange2 data", is_text=False)
                    step_data["KEYEXCHANGE2"] = ke2_data
                    transcript_hash.update(ke2_frame)
                    transcript = transcript_hash.copy().finalize()

            elif step_type == "KEYCONFIRM1":
                if action == "send":
                    kc1_data = os.urandom(32)
                    step_data["KEYCONFIRM1"] = kc1_data
                    kc1 = b"KEYCONFIRM1|" + kc1_data
                    s.sendall(pack(kc1))
                    transcript_hash.update(kc1)
                    transcript = transcript_hash.copy().finalize()
                else:  # recv
                    kc1_frame = recv_frame(s)
                    kc1_data = parse_protocol_frame(kc1_frame, b"KEYCONFIRM1")
                    validate_field(kc1_data, 32, 32, "KeyConfirm1 data", is_text=False)
                    step_data["KEYCONFIRM1"] = kc1_data
                    transcript_hash.update(kc1_frame)
                    transcript = transcript_hash.copy().finalize()

            elif step_type == "KEYCONFIRM2":
                if action == "send":
                    kc2_data = os.urandom(32)
                    step_data["KEYCONFIRM2"] = kc2_data
                    kc2 = b"KEYCONFIRM2|" + kc2_data
                    s.sendall(pack(kc2))
                    transcript_hash.update(kc2)
                    transcript = transcript_hash.copy().finalize()
                else:  # recv
                    kc2_frame = recv_frame(s)
                    kc2_data = parse_protocol_frame(kc2_frame, b"KEYCONFIRM2")
                    validate_field(kc2_data, 32, 32, "KeyConfirm2 data", is_text=False)
                    step_data["KEYCONFIRM2"] = kc2_data
                    transcript_hash.update(kc2_frame)
                    transcript = transcript_hash.copy().finalize()

        # 确保所有步骤数据都已收集
        required_keys = {"KEYEXCHANGE1", "KEYEXCHANGE2", "KEYCONFIRM1", "KEYCONFIRM2"}
        if set(step_data.keys()) != required_keys:
            raise ProtocolError("Missing step data after random order execution")

        # ==== 状态13: 发送ClientAuth并接收ServerAuth ====
        logger.info("Step 13/13: Sending ClientAuth and completing handshake")
        sig_client = client_priv.sign(transcript)
        auth_msg = b"CLIENTAUTH|" + sig_client
        s.sendall(pack(auth_msg))
        transcript_hash.update(auth_msg)
        transcript = transcript_hash.copy().finalize()
        current_state = "CLIENTAUTH_SENT"

        # 接收ServerAuth
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

        # 接收SecureAck
        ack_frame = recv_frame(s)
        if current_state != "SERVERAUTH_RECEIVED":
            raise ProtocolError("Invalid state for SecureAck")
        current_state = "SECUREACK_RECEIVED"

        # 派生最终会话密钥
        info = b"SC-HKDF|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|" + nonce_c + b"|" + nonce_s
        info += b"|" + step_data["KEYEXCHANGE1"] + b"|" + step_data["KEYEXCHANGE2"]
        info += b"|" + step_data["KEYCONFIRM1"] + b"|" + step_data["KEYCONFIRM2"]
        okm = hkdf(shared, info, length=64)
        k_c2s = okm[:32]  # 客户端到服务端的密钥
        k_s2c = okm[32:]  # 服务端到客户端的密钥

        sess = Session(send_key=k_c2s, recv_key=k_s2c, seed_code=seed_code, role="client")

        ct = parse_protocol_frame(ack_frame, b"SECUREACK")
        try:
            ack = sess.decrypt(ct, aad=transcript)
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