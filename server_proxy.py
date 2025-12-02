#!/usr/bin/env python3
# server_proxy.py
"""
Sovereign-Chain Server Proxy - 接收加密流量并转发到真实服务
"""
import socket
import threading
import logging
import struct
import time
from collections import deque
from server import handle_conn, recv_frame, pack, FRAME_HDR, Session

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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


def recv_exact(sock, n):
    """从socket精确接收n字节数据"""
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


class ServerProxy:
    def __init__(self, listen_host='0.0.0.0', listen_port=5555,
                 target_host='127.0.0.1', target_port=3389):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.running = False

    def handle_proxy_connection(self, client_sock, client_addr, server_priv, server_cert, ca_cert):
        """处理代理连接 - 集成server.py的握手逻辑"""
        logger.info(f"Handling proxy connection from {client_addr}")
        target_sock = None
        session = None

        try:
            # 连接到真实目标服务
            logger.info(f"Connecting to target service {self.target_host}:{self.target_port}")
            target_sock = socket.create_connection((self.target_host, self.target_port))
            target_sock.setblocking(True)
            logger.info("Connected to target service")

            # 复用server.py的握手逻辑
            from server import handle_conn_wrapper
            import io
            import contextlib

            # 创建临时包装器来处理握手
            class ConnectionWrapper:
                def __init__(self, sock):
                    self.sock = sock
                    self.session = None
                    self.handshake_complete = False

                def settimeout(self, timeout):
                    self.sock.settimeout(timeout)

                def close(self):
                    self.sock.close()

            conn_wrapper = ConnectionWrapper(client_sock)

            # 执行握手（复用server.py逻辑）
            try:
                # 这里我们需要修改handle_conn函数来返回session而不是进入循环
                session = self.custom_handshake(conn_wrapper, client_addr, server_priv, server_cert, ca_cert)
                if session is None:
                    raise Exception("Handshake failed")

                logger.info("Handshake completed successfully")

            except Exception as e:
                safe_log_error(f"Handshake failed for {client_addr}: {str(e)}")
                return

            # 启动双向数据转发
            client_to_target_thread = threading.Thread(
                target=self.forward_client_to_target,
                args=(client_sock, target_sock, session, client_addr)
            )
            target_to_client_thread = threading.Thread(
                target=self.forward_target_to_client,
                args=(client_sock, target_sock, session, client_addr)
            )

            client_to_target_thread.daemon = True
            target_to_client_thread.daemon = True

            client_to_target_thread.start()
            target_to_client_thread.start()

            # 等待任意线程结束
            client_to_target_thread.join()
            target_to_client_thread.join()

        except Exception as e:
            safe_log_error(f"Error handling proxy connection {client_addr}: {str(e)}")
        finally:
            if target_sock:
                target_sock.close()
            logger.info(f"Proxy connection {client_addr} closed")

    def custom_handshake(self, conn_wrapper, addr, server_priv, server_cert, ca_cert):
        """自定义握手逻辑，返回session对象"""
        from server import recv_frame, pack, ProtocolError, Session
        from server import hkdf, nonce_from_seq, parse_protocol_frame, validate_field
        from server import check_nonce_replay, load_anonymous_ca_cert
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from cryptography.exceptions import InvalidSignature
        from cryptography import x509
        import os
        import secrets
        import random
        import time

        conn = conn_wrapper.sock
        transcript_hash = hashes.Hash(hashes.SHA256())
        handshake_start_time = time.time()
        current_state = "INIT"

        try:
            conn.settimeout(30)  # 握手超时

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

            if not check_nonce_replay(nonce_c, addr):
                raise ValueError("nonce reuse detected")

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
                client_cert = x509.load_pem_x509_certificate(client_cert_pem)
            except Exception as e:
                raise ValueError(f"Failed to load client certificate: {str(e)}")
            transcript_hash.update(ccert_frame)
            transcript = transcript_hash.copy().finalize()

            # ==== 状态6: 验证客户端证书 ====
            logger.info(f"Step 6/13: Verifying client certificate from {addr}")
            try:
                ca_pub = ca_cert.public_key()
                if not hasattr(ca_pub, 'verify'):
                    raise ValueError("CA public key cannot verify")
                ca_pub.verify(client_cert.signature, client_cert.tbs_certificate_bytes)
                logger.info(f"Client certificate verified successfully for {addr}")
            except (InvalidSignature, ValueError):
                try:
                    anonymous_ca_cert = load_anonymous_ca_cert()
                    anon_ca_pub = anonymous_ca_cert.public_key()
                    anon_ca_pub.verify(client_cert.signature, client_cert.tbs_certificate_bytes)
                    logger.info(f"Client certificate verified successfully for {addr} (using anonymous CA)")
                except (InvalidSignature, ValueError) as e:
                    raise ValueError(f"Client certificate verification failed: {str(e)}")
            except Exception as e:
                raise ValueError(f"Client certificate verification failed: {str(e)}")

            # ==== 状态7: 计算共享密钥 ====
            logger.info(f"Step 7/13: Calculating shared key for {addr}")
            shared = server_eph.exchange(x25519.X25519PublicKey.from_public_bytes(client_eph_pub))

            # ==== 状态8: 生成并发送种子码 ====
            logger.info(f"Step 8/13: Sending SeedCode to {addr}")
            if current_state != "CLIENTCERTSEND_RECEIVED":
                raise ProtocolError("Invalid state for SeedCode")
            current_state = "SEEDCODE_SENT"

            seed_nonce = os.urandom(8)
            seed_code = os.urandom(32) + secrets.token_bytes(32)
            order_seed = os.urandom(32)

            steps = [
                ("KEYEXCHANGE1", "send", "KeyExchange1"),
                ("KEYEXCHANGE2", "recv", "KeyExchange2"),
                ("KEYCONFIRM1", "send", "KeyConfirm1"),
                ("KEYCONFIRM2", "recv", "KeyConfirm2")
            ]

            rng = random.Random(order_seed)
            step_order = list(range(len(steps)))
            rng.shuffle(step_order)

            step_names = [steps[i][0] for i in step_order]
            logger.info(f"Generated step order: {step_names} for {addr}")

            digest = hashes.Hash(hashes.SHA256())
            digest.update(client_cert.public_bytes(serialization.Encoding.DER))
            client_fingerprint = digest.finalize()[:16]

            seed_payload = b"SEEDCODE|" + seed_nonce + seed_code + order_seed + client_fingerprint

            # 使用临时密钥加密种子码
            info = b"SC-HKDF|SC-EE-1|X25519-Ed25519-CHACHA20POLY1305-HKDFSHA256|" + nonce_c + b"|" + nonce_s
            temp_key = hkdf(shared, info, length=64)
            k_s2c = temp_key[32:]

            temp_aead = ChaCha20Poly1305(k_s2c)
            temp_nonce = transcript[:12]
            encrypted_payload = temp_aead.encrypt(temp_nonce, seed_payload, transcript)
            conn.sendall(pack(encrypted_payload))
            transcript_hash.update(encrypted_payload)
            transcript = transcript_hash.copy().finalize()

            # ==== 状态9-12: 根据随机顺序执行步骤 ====
            step_data = {}
            step_counter = 9

            for step_idx in step_order:
                step_type, action, step_name = steps[step_idx]
                logger.info(
                    f"Step {9 + step_idx}/13: {'Sending' if action == 'send' else 'Waiting for'} {step_name} to {addr}")
                step_counter += 1

                if step_type == "KEYEXCHANGE1":
                    if action == "send":
                        ke1_data = os.urandom(32)
                        step_data["KEYEXCHANGE1"] = ke1_data
                        ke1 = b"KEYEXCHANGE1|" + ke1_data
                        conn.sendall(pack(ke1))
                        transcript_hash.update(ke1)
                        transcript = transcript_hash.copy().finalize()
                    else:
                        ke1_frame = recv_frame(conn)
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
                        conn.sendall(pack(ke2))
                        transcript_hash.update(ke2)
                        transcript = transcript_hash.copy().finalize()
                    else:
                        ke2_frame = recv_frame(conn)
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
                        conn.sendall(pack(kc1))
                        transcript_hash.update(kc1)
                        transcript = transcript_hash.copy().finalize()
                    else:
                        kc1_frame = recv_frame(conn)
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
                        conn.sendall(pack(kc2))
                        transcript_hash.update(kc2)
                        transcript = transcript_hash.copy().finalize()
                    else:
                        kc2_frame = recv_frame(conn)
                        kc2_data = parse_protocol_frame(kc2_frame, b"KEYCONFIRM2")
                        validate_field(kc2_data, 32, 32, "KeyConfirm2 data", is_text=False)
                        step_data["KEYCONFIRM2"] = kc2_data
                        transcript_hash.update(kc2_frame)
                        transcript = transcript_hash.copy().finalize()

            # 确保所有步骤数据都已收集
            required_keys = {"KEYEXCHANGE1", "KEYEXCHANGE2", "KEYCONFIRM1", "KEYCONFIRM2"}
            if set(step_data.keys()) != required_keys:
                raise ProtocolError("Missing step data after random order execution")

            # ==== 状态13: 接收ClientAuth并发送ServerAuth ====
            logger.info(f"Step 13/13: Waiting for ClientAuth from {addr}")
            caut_frame = recv_frame(conn)
            if current_state != "SEEDCODE_SENT":
                raise ProtocolError("Invalid state for ClientAuth")
            current_state = "CLIENTAUTH_RECEIVED"

            sig_client = parse_protocol_frame(caut_frame, b"CLIENTAUTH")
            client_pub = client_cert.public_key()

            try:
                client_pub.verify(sig_client, transcript)
                logger.info(f"Client signature verified successfully for {addr}")
            except InvalidSignature:
                raise ValueError("client signature verification failed")

            transcript_hash.update(caut_frame)
            transcript = transcript_hash.copy().finalize()

            # 发送ServerAuth
            sig_server = server_priv.sign(transcript)
            sa = b"SERVERAUTH|" + sig_server
            conn.sendall(pack(sa))
            transcript_hash.update(sa)
            transcript = transcript_hash.copy().finalize()
            current_state = "SERVERAUTH_SENT"

            # ==== 创建会话并发送SecureAck ====
            info = b"SC-HKDF|SC-EE-1|X25519-Ed25519-CHACHA20POLY1305-HKDFSHA256|" + nonce_c + b"|" + nonce_s
            info += b"|" + step_data["KEYEXCHANGE1"] + b"|" + step_data["KEYEXCHANGE2"]
            info += b"|" + step_data["KEYCONFIRM1"] + b"|" + step_data["KEYCONFIRM2"]
            okm = hkdf(shared, info, length=64)
            k_c2s = okm[:32]  # 客户端到服务端的密钥
            k_s2c = okm[32:]  # 服务端到客户端的密钥

            session = Session(send_key=k_s2c, recv_key=k_c2s, seed_code=seed_code, role="server")
            ct = session.encrypt(b"ACK", aad=transcript)
            conn.sendall(pack(b"SECUREACK|" + ct))
            current_state = "SECUREACK_SENT"

            handshake_time = time.time() - handshake_start_time
            logger.info(f"Handshake completed with {addr} (耗时: {handshake_time:.2f}s)")

            conn.settimeout(None)
            return session

        except Exception as e:
            safe_log_error(f"Handshake error with {addr}: {str(e)}")
            return None

    def encrypt_and_send(self, session, sock, data, client_addr):
        """加密数据并发送到客户端"""
        try:
            current_seq = session.send_seq
            header = struct.pack(">Q", current_seq)
            ct = session.encrypt(data)
            data_frame = b"DATA" + header + ct
            sock.sendall(pack(data_frame))
            return True
        except Exception as e:
            safe_log_error(f"Encryption/send error for client {client_addr}: {str(e)}")
            return False

    def receive_and_decrypt(self, session, sock, client_addr):
        """接收并解密客户端数据"""
        try:
            frm = recv_frame(sock)

            if not frm.startswith(b"DATA"):
                logger.warning(f"Received non-DATA frame from {client_addr}")
                return None

            if len(frm) < 12:
                logger.warning(f"Invalid response frame format from {client_addr}")
                return None

            resp_seq = struct.unpack(">Q", frm[4:12])[0]
            resp_ct = frm[12:]

            if resp_seq != session.recv_seq:
                logger.warning(
                    f"Sequence number mismatch for {client_addr}: expected {session.recv_seq}, got {resp_seq}")
                return None

            try:
                decrypted_data = session.decrypt(resp_ct)
                return decrypted_data
            except Exception as e:
                safe_log_error(f"Decryption error for client {client_addr}: {str(e)}")
                return None

        except Exception as e:
            safe_log_error(f"Receive error for client {client_addr}: {str(e)}")
            return None

    def forward_client_to_target(self, client_sock, target_sock, session, client_addr):
        """将客户端数据转发到目标服务（解密）"""
        try:
            while True:
                # 从客户端接收并解密数据
                decrypted_data = self.receive_and_decrypt(session, client_sock, client_addr)
                if decrypted_data is None:
                    break

                # 发送解密后的数据到目标服务
                target_sock.sendall(decrypted_data)

        except Exception as e:
            safe_log_error(f"Client->Target forwarding error for {client_addr}: {str(e)}")

    def forward_target_to_client(self, client_sock, target_sock, session, client_addr):
        """将目标服务数据转发到客户端（加密）"""
        try:
            while True:
                # 从目标服务读取数据
                data = target_sock.recv(4096)
                if not data:
                    logger.info(f"Target service closed connection for {client_addr}")
                    break

                # 加密并发送到客户端
                if not self.encrypt_and_send(session, client_sock, data, client_addr):
                    break

        except Exception as e:
            safe_log_error(f"Target->Client forwarding error for {client_addr}: {str(e)}")

    def start(self, server_priv, server_cert, ca_cert):
        """启动服务端代理"""
        self.running = True
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((self.listen_host, self.listen_port))
            server_socket.listen(5)
            logger.info(f"Server proxy listening on {self.listen_host}:{self.listen_port}")
            logger.info(f"Forwarding to target service {self.target_host}:{self.target_port}")

            while self.running:
                try:
                    client_sock, client_addr = server_socket.accept()
                    logger.info(f"Accepted connection from {client_addr}")

                    # 为每个客户端创建新线程
                    client_thread = threading.Thread(
                        target=self.handle_proxy_connection,
                        args=(client_sock, client_addr, server_priv, server_cert, ca_cert)
                    )
                    client_thread.daemon = True
                    client_thread.start()

                except Exception as e:
                    safe_log_error(f"Error accepting connection: {str(e)}")

        except Exception as e:
            safe_log_error(f"Server proxy error: {str(e)}")
        finally:
            server_socket.close()
            logger.info("Server proxy stopped")

    def stop(self):
        """停止服务端代理"""
        self.running = False


def main():
    """主函数"""
    from server import load_pem_priv, load_pem_cert, load_ca_cert

    # 配置参数
    LISTEN_HOST = '0.0.0.0'  # 监听地址（client_proxy连接这里）
    LISTEN_PORT = 25555  # 监听端口（Sovereign-Chain默认端口）
    TARGET_HOST = 'yuanbao.tencent.com'  # 真实目标服务地址
    TARGET_PORT = 443  # 真实目标服务端口（RDP默认端口）

    try:
        server_priv = load_pem_priv()
        server_cert = load_pem_cert()
        ca_cert = load_ca_cert()
        logger.info("Server credentials loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load server credentials: {str(e)}")
        return

    proxy = ServerProxy(
        listen_host=LISTEN_HOST,
        listen_port=LISTEN_PORT,
        target_host=TARGET_HOST,
        target_port=TARGET_PORT
    )

    try:
        proxy.start(server_priv, server_cert, ca_cert)
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down...")
    except Exception as e:
        safe_log_error(f"Server proxy fatal error: {str(e)}")
    finally:
        proxy.stop()


if __name__ == "__main__":
    main()