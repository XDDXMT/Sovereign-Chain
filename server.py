#!/usr/bin/env python3
# server.py
"""
Sovereign-Chain Server - 12次超级无敌宇宙加密握手版本 + 种子码动态加密
"""

import socket, struct, os, threading, time, logging
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import secrets
# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

FRAME_HDR = 4
PROTO_VER = b"SC-EE-1"
CIPHER_SUITE = b"X25519-Ed25519-CHACHA20POLY1305-HKDFSHA256"
HANDSHAKE_TIMEOUT = 30  # 握手超时时间（秒）

# 用于防止重放攻击的nonce缓存
nonce_cache = {}
nonce_cache_lock = threading.Lock()
NONCE_CACHE_MAX_SIZE = 10000
NONCE_CACHE_EXPIRE = 300  # 5分钟

# 在 Session 类上方添加新的异常类
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
        if l > 50_000_000:
            raise ValueError("frame too large")
        return recv_exact(sock, l)
    except Exception as e:
        raise ConnectionError(f"failed to receive frame: {str(e)}")


def load_pem_priv(path):
    try:
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
    except Exception as e:
        raise ValueError(f"failed to load private key: {str(e)}")


def load_pem_cert(path):
    try:
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(
                f.read(),
                backend=default_backend()
            )
    except Exception as e:
        raise ValueError(f"failed to load certificate: {str(e)}")


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


class Session:
    def __init__(self, send_key, recv_key, seed_code):
        self.send_base_key = send_key
        self.recv_base_key = recv_key
        self.seed_code = seed_code
        # ==== 修复：序列号从1开始 ====
        self.send_seq = 1  # 初始为1
        self.recv_seq = 1  # 初始为1
        self.send_label = b"server->client"
        self.recv_label = b"client->server"

    def _derive_key(self, base_key, seq, label):
        """使用种子码和序列号派生动态密钥"""
        info = self.seed_code + struct.pack(">Q", seq) + label
        return hkdf(base_key, info, length=32)

    def encrypt(self, pt: bytes, aad: bytes = b""):
        # 派生本次消息的动态密钥
        dynamic_key = self._derive_key(self.send_base_key, self.send_seq, self.send_label)
        aead = ChaCha20Poly1305(dynamic_key)

        n = nonce_from_seq(self.send_seq, self.send_label)
        self.send_seq += 1
        return aead.encrypt(n, pt, aad)

    def decrypt(self, ct: bytes, aad: bytes = b""):
        # 派生本次消息的动态密钥
        dynamic_key = self._derive_key(self.recv_base_key, self.recv_seq, self.recv_label)
        aead = ChaCha20Poly1305(dynamic_key)

        n = nonce_from_seq(self.recv_seq, self.recv_label)
        pt = aead.decrypt(n, ct, aad)
        self.recv_seq += 1
        return pt


def handle_conn(conn, addr, server_priv, server_cert, ca_cert):
    logger.info(f"connection from {addr}")
    transcript_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    handshake_start_time = time.time()

    try:
        # 设置握手超时
        conn.settimeout(HANDSHAKE_TIMEOUT)

        logger.info(f"Step 1/12: Waiting for ClientHello from {addr}")
        # 1) ClientHello
        ch = recv_frame(conn)
        if not ch.startswith(b"CLIENTHELLO|"):
            raise ValueError("expected CLIENTHELLO")
        payload = ch.split(b"|", 1)[1]
        if len(payload) != 48:  # 32字节公钥 + 16字节nonce
            raise ValueError("invalid ClientHello payload length")

        client_eph_pub = payload[:32]
        nonce_c = payload[32:48]

        # 检查nonce是否重复使用
        if not check_nonce_replay(nonce_c, addr):
            raise ValueError("nonce reuse detected - possible replay attack")

        transcript_hash.update(ch)
        transcript = transcript_hash.copy().finalize()

        logger.info(f"Step 2/12: Sending ServerHello to {addr}")
        # 2) ServerHello
        server_eph = x25519.X25519PrivateKey.generate()
        server_eph_pub = server_eph.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
        nonce_s = os.urandom(16)
        sh = b"SERVERHELLO|" + server_eph_pub + nonce_s
        conn.sendall(pack(sh))
        transcript_hash.update(sh)
        transcript = transcript_hash.copy().finalize()

        logger.info(f"Step 3/12: Sending ServerCertSend to {addr}")
        # 3) ServerCertSend
        scert = b"SERVERCERTSEND|" + server_cert.public_bytes(serialization.Encoding.PEM)
        conn.sendall(pack(scert))
        transcript_hash.update(scert)
        transcript = transcript_hash.copy().finalize()

        logger.info(f"Step 4/12: Sending ClientCertRequest to {addr}")
        # 4) ClientCertRequest
        ccr = b"CLIENTCERTREQUEST|"
        conn.sendall(pack(ccr))
        transcript_hash.update(ccr)
        transcript = transcript_hash.copy().finalize()

        logger.info(f"Step 5/12: Waiting for ClientCertSend from {addr}")
        # 5) ClientCertSend
        ccert_frame = recv_frame(conn)
        if not ccert_frame.startswith(b"CLIENTCERTSEND|"):
            raise ValueError("expected CLIENTCERTSEND")
        client_cert_pem = ccert_frame.split(b"|", 1)[1]
        client_cert = x509.load_pem_x509_certificate(
            client_cert_pem,
            backend=default_backend()
        )
        transcript_hash.update(ccert_frame)
        transcript = transcript_hash.copy().finalize()

        logger.info(f"Step 6/12: Verifying client certificate from {addr}")
        # 验证客户端证书
        ca_pub = ca_cert.public_key()
        try:
            # 验证证书签名
            if not isinstance(ca_pub, ed25519.Ed25519PublicKey):
                raise ValueError("CA public key is not Ed25519")

            # 对于Ed25519，直接验证签名
            ca_pub.verify(
                client_cert.signature,
                client_cert.tbs_certificate_bytes
            )
            logger.info(f"Client certificate verified successfully for {addr}")
        except InvalidSignature:
            raise ValueError("client certificate signature invalid")
        except Exception as e:
            raise ValueError(f"client certificate verification failed: {str(e)}")

        logger.info(f"Step 7/12: Sending KeyExchange1 to {addr}")
        # 6) KeyExchange1 - 额外的密钥交换数据
        ke1_data = os.urandom(32)
        ke1 = b"KEYEXCHANGE1|" + ke1_data
        conn.sendall(pack(ke1))
        transcript_hash.update(ke1)
        transcript = transcript_hash.copy().finalize()

        logger.info(f"Step 8/12: Waiting for KeyExchange2 from {addr}")
        # 7) KeyExchange2 - 额外的密钥交换数据
        ke2_frame = recv_frame(conn)
        if not ke2_frame.startswith(b"KEYEXCHANGE2|"):
            raise ValueError("expected KEYEXCHANGE2")
        ke2_data = ke2_frame.split(b"|", 1)[1]
        if len(ke2_data) != 32:
            raise ValueError("invalid KeyExchange2 data length")
        transcript_hash.update(ke2_frame)
        transcript = transcript_hash.copy().finalize()

        logger.info(f"Step 9/12: Sending KeyConfirm1 to {addr}")
        # 8) KeyConfirm1 - 密钥确认
        kc1_data = os.urandom(32)
        kc1 = b"KEYCONFIRM1|" + kc1_data
        conn.sendall(pack(kc1))
        transcript_hash.update(kc1)
        transcript = transcript_hash.copy().finalize()

        logger.info(f"Step 10/12: Waiting for KeyConfirm2 from {addr}")
        # 9) KeyConfirm2 - 密钥确认
        kc2_frame = recv_frame(conn)
        if not kc2_frame.startswith(b"KEYCONFIRM2|"):
            raise ValueError("expected KEYCONFIRM2")
        kc2_data = kc2_frame.split(b"|", 1)[1]
        if len(kc2_data) != 32:
            raise ValueError("invalid KeyConfirm2 data length")
        transcript_hash.update(kc2_frame)
        transcript = transcript_hash.copy().finalize()

        logger.info(f"Step 11/12: Calculating shared key for {addr}")
        # 计算共享密钥（包含额外的密钥交换数据）
        shared = server_eph.exchange(x25519.X25519PublicKey.from_public_bytes(client_eph_pub))

        # 使用结构化的info参数进行密钥派生
        info = b"SC-HKDF|" + PROTO_VER + b"|" + CIPHER_SUITE + b"|" + nonce_c + b"|" + nonce_s
        info += b"|" + ke1_data + b"|" + ke2_data + b"|" + kc1_data + b"|" + kc2_data

        okm = hkdf(shared, info, length=64)
        k_c2s = okm[:32]
        k_s2c = okm[32:]

        # 销毁临时密钥以确保前向安全性
        del server_eph

        # ==== 新增：生成并发送种子码 ====
        logger.info(f"Step 12/12: Sending SeedCode to {addr}")
        # ==== 修复：添加seed_payload定义 ====
        seed_nonce = os.urandom(8)
        seed_code = os.urandom(32) + secrets.token_bytes(32)  # 64字节高熵种子码
        seed_payload = b"SEEDCODE|" + seed_nonce + seed_code

        # ==== 修复：完整加密消息类型 ====
        temp_aead = ChaCha20Poly1305(k_s2c)
        temp_nonce = transcript[:12]
        aad_data = transcript  # 只使用 transcript 作为关联数据
        encrypted_payload = temp_aead.encrypt(temp_nonce, seed_payload, aad_data)

        conn.sendall(pack(encrypted_payload))
        transcript_hash.update(encrypted_payload)
        transcript = transcript_hash.copy().finalize()

        logger.info(f"Step 13/13: Waiting for ClientAuth from {addr}")
        # 10) ClientAuth: client signature over transcript
        caut = recv_frame(conn)
        if not caut.startswith(b"CLIENTAUTH|"):
            raise ValueError("expected CLIENTAUTH")
        sig_client = caut.split(b"|", 1)[1]

        # 使用证书中的公钥验证客户端签名
        client_pub = client_cert.public_key()
        if not isinstance(client_pub, ed25519.Ed25519PublicKey):
            raise ValueError("client public key is not Ed25519")

        try:
            client_pub.verify(sig_client, transcript)
            logger.info(f"Client signature verified successfully for {addr}")
        except InvalidSignature:
            raise ValueError("client signature verification failed")

        transcript_hash.update(caut)
        transcript = transcript_hash.copy().finalize()

        # 11) ServerAuth: server signs transcript and sends
        sig_server = server_priv.sign(transcript)
        sa = b"SERVERAUTH|" + sig_server
        conn.sendall(pack(sa))
        transcript_hash.update(sa)
        transcript = transcript_hash.copy().finalize()

        # 12) SecureAck: encrypted "ACK"
        # 使用种子码创建会话
        sess = Session(send_key=k_s2c, recv_key=k_c2s, seed_code=seed_code)
        ct = sess.encrypt(b"ACK", aad=transcript)
        conn.sendall(pack(b"SECUREACK|" + ct))

        handshake_time = time.time() - handshake_start_time
        logger.info(f"13次握手完成 with {addr} (耗时: {handshake_time:.2f}s)")

        # 重置超时设置
        conn.settimeout(None)

        # 后续加密通信（示例 echo）
        while True:
            try:
                frm = recv_frame(conn)
            except ConnectionError as e:
                logger.error(f"Connection error with {addr}: {str(e)}")
                break

            # ==== 修复：解析帧 ====
            def parse_frame(frame):
                """严格帧解析器"""
                try:
                    if frame.startswith(b"DATA"):
                        if len(frame) < 12:  # 4字节前缀 + 8字节序列号
                            return None
                        seq_bytes = frame[4:12]
                        seq = struct.unpack(">Q", seq_bytes)[0]
                        ct = frame[12:]
                        return ("DATA", seq, ct)
                    return None
                except:
                    return None

            parsed = parse_frame(frm)
            if not parsed:
                logger.warning(f"Invalid frame format from {addr}")
                break

            frame_type, recv_seq, ct = parsed

            # ==== 修复：序列号检查 ====
            if recv_seq != sess.recv_seq:
                logger.warning(f"Sequence number mismatch from {addr}: expected {sess.recv_seq}, got {recv_seq}")
                break

            try:
                pt = sess.decrypt(ct)
            except Exception as e:
                logger.error(f"Decryption error from {addr}: {str(e)}")
                break

            logger.info(f"Received from {addr}: {pt}")

            # ==== 修复：添加序列号到响应 ====
            # 获取当前发送序列号
            current_seq = sess.send_seq
            # 序列号编码为8字节大端序
            header = struct.pack(">Q", current_seq)
            # 加密响应
            resp = b"echo: " + pt
            ct_resp = sess.encrypt(resp)
            # 构建响应帧
            data_frame = b"DATA" + header + ct_resp
            # 发送响应
            try:
                conn.sendall(pack(data_frame))
            except Exception as e:
                logger.error(f"Failed to send response to {addr}: {str(e)}")
                break

    except socket.timeout:
        logger.error(f"Handshake timeout with {addr}")
    except Exception as e:
        logger.error(f"Connection error with {addr}: {type(e).__name__}: {str(e)}")
    finally:
        conn.close()


def main():
    try:
        server_priv = load_pem_priv("server_key.pem")
        server_cert = load_pem_cert("server_cert.pem")
        ca_cert = load_pem_cert("ca_cert.pem")
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
                target=handle_conn,
                args=(conn, addr, server_priv, server_cert, ca_cert),
                daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
    finally:
        s.close()


if __name__ == "__main__":
    main()