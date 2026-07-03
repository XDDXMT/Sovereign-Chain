#!/usr/bin/env python3
# client_proxy.py
"""
Sovereign-Chain Client Proxy - 将TCP流量通过Sovereign-Chain加密转发
"""
import socket
import threading
import logging
import struct
import time
import os
from collections import deque
from client import client_handshake, Session, recv_frame, pack, FRAME_HDR

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


def close_socket(sock):
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


class ClientProxy:
    def __init__(self, listen_host='127.0.0.1', listen_port=3389,
                 server_host='127.0.0.1', server_port=5555):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.server_host = server_host
        self.server_port = server_port
        self.running = False

    def handle_client_connection(self, client_sock, client_addr):
        """处理单个客户端连接"""
        logger.info(f"New client connection from {client_addr}")
        server_session = None
        server_sock = None

        try:
            # 连接到Sovereign-Chain服务器并执行握手
            logger.info(f"Connecting to Sovereign-Chain server {self.server_host}:{self.server_port}")
            server_session, server_sock = client_handshake(self.server_host, self.server_port)
            logger.info("Handshake completed successfully")

            # 设置socket为阻塞模式
            client_sock.setblocking(True)
            server_sock.setblocking(True)

            # 启动双向数据转发
            client_to_server_thread = threading.Thread(
                target=self.forward_client_to_server,
                args=(client_sock, server_sock, server_session, client_addr)
            )
            server_to_client_thread = threading.Thread(
                target=self.forward_server_to_client,
                args=(client_sock, server_sock, server_session, client_addr)
            )

            client_to_server_thread.daemon = True
            server_to_client_thread.daemon = True

            client_to_server_thread.start()
            server_to_client_thread.start()

            # 等待任意线程结束
            client_to_server_thread.join()
            server_to_client_thread.join()

        except Exception as e:
            safe_log_error(f"Error handling client {client_addr}: {str(e)}")
        finally:
            close_socket(server_sock)
            close_socket(client_sock)
            logger.info(f"Client connection {client_addr} closed")

    def encrypt_and_send(self, session, sock, data, client_addr):
        """加密数据并通过Sovereign-Chain发送"""
        try:
            current_seq, ct = session.encrypt_with_sequence(data)
            header = struct.pack(">Q", current_seq)
            data_frame = b"DATA" + header + ct
            sock.sendall(pack(data_frame))
            return True
        except Exception as e:
            safe_log_error(f"Encryption/send error for client {client_addr}: {str(e)}")
            return False

    def receive_and_decrypt(self, session, sock, client_addr):
        """接收并解密Sovereign-Chain数据"""
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
                decrypted_data = session.decrypt_with_sequence(resp_seq, resp_ct)
                return decrypted_data
            except Exception as e:
                safe_log_error(f"Decryption error for client {client_addr}: {str(e)}")
                return None

        except Exception as e:
            safe_log_error(f"Receive error for client {client_addr}: {str(e)}")
            return None

    def forward_client_to_server(self, client_sock, server_sock, session, client_addr):
        """将客户端数据转发到服务器（加密）"""
        try:
            while True:
                # 从客户端读取数据
                data = client_sock.recv(4096)
                if not data:
                    logger.info(f"Client {client_addr} closed connection")
                    break

                # 加密并发送到Sovereign-Chain服务器
                if not self.encrypt_and_send(session, server_sock, data, client_addr):
                    break

        except Exception as e:
            safe_log_error(f"Client->Server forwarding error for {client_addr}: {str(e)}")
        finally:
            close_socket(client_sock)
            close_socket(server_sock)

    def forward_server_to_client(self, client_sock, server_sock, session, client_addr):
        """将服务器数据转发到客户端（解密）"""
        try:
            while True:
                # 从Sovereign-Chain服务器接收并解密数据
                decrypted_data = self.receive_and_decrypt(session, server_sock, client_addr)
                if decrypted_data is None:
                    break

                # 发送解密后的数据到客户端
                client_sock.sendall(decrypted_data)

        except Exception as e:
            safe_log_error(f"Server->Client forwarding error for {client_addr}: {str(e)}")
        finally:
            close_socket(server_sock)
            close_socket(client_sock)

    def start(self):
        """启动客户端代理"""
        self.running = True
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((self.listen_host, self.listen_port))
            server_socket.listen(5)
            logger.info(f"Client proxy listening on {self.listen_host}:{self.listen_port}")
            logger.info(f"Forwarding to Sovereign-Chain server {self.server_host}:{self.server_port}")

            while self.running:
                try:
                    client_sock, client_addr = server_socket.accept()
                    logger.info(f"Accepted connection from {client_addr}")

                    # 为每个客户端创建新线程
                    client_thread = threading.Thread(
                        target=self.handle_client_connection,
                        args=(client_sock, client_addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()

                except Exception as e:
                    safe_log_error(f"Error accepting connection: {str(e)}")

        except Exception as e:
            safe_log_error(f"Client proxy error: {str(e)}")
        finally:
            server_socket.close()
            logger.info("Client proxy stopped")

    def stop(self):
        """停止客户端代理"""
        self.running = False


def main():
    """主函数"""
    # 配置参数
    LISTEN_HOST = os.getenv('SC_CLIENT_PROXY_LISTEN_HOST', '127.0.0.1')
    LISTEN_PORT = int(os.getenv('SC_CLIENT_PROXY_LISTEN_PORT', '3398'))
    SERVER_HOST = os.getenv('SC_SERVER_HOST', '127.0.0.1')
    SERVER_PORT = int(os.getenv('SC_SERVER_PORT', '25558'))

    proxy = ClientProxy(
        listen_host=LISTEN_HOST,
        listen_port=LISTEN_PORT,
        server_host=SERVER_HOST,
        server_port=SERVER_PORT
    )

    try:
        proxy.start()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down...")
    except Exception as e:
        safe_log_error(f"Client proxy fatal error: {str(e)}")
    finally:
        proxy.stop()


if __name__ == "__main__":
    main()
