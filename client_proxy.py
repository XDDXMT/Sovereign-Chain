import socket
import threading

# 目标服务器地址
TARGET_HOST = "127.0.0.1"   # 真正服务器
TARGET_PORT = 25566          # 真正服务器端口

# 代理监听地址
PROXY_HOST = "0.0.0.0"
PROXY_PORT = 8888           # 客户端连这个端口


def handle_client(client_socket, target_host, target_port):
    """处理客户端连接，转发数据到目标服务器"""
    try:
        # 连接真正的服务器
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((target_host, target_port))
        print(f"[MITM] 已连接目标服务器 {target_host}:{target_port}")

        # 启动两个线程：客户端->服务端，服务端->客户端
        def forward(src, dst, direction):
            while True:
                try:
                    data = src.recv(4096)
                    if not data:
                        break
                    print(f"[MITM] {direction} frame len={len(data)} bytes, first 50: {data[:50]!r}")
                    dst.sendall(data)
                except Exception:
                    break

        threading.Thread(target=forward, args=(client_socket, server_socket, "C->S")).start()
        threading.Thread(target=forward, args=(server_socket, client_socket, "S->C")).start()

    except Exception as e:
        print(f"[!] 代理错误: {e}")
        client_socket.close()


def start_proxy(proxy_host, proxy_port, target_host, target_port):
    """启动代理"""
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy.bind((proxy_host, proxy_port))
    proxy.listen(5)
    print(f"[MITM] 代理已启动 {proxy_host}:{proxy_port} -> {target_host}:{target_port}")

    while True:
        client_socket, addr = proxy.accept()
        print(f"[MITM] 客户端连接: {addr}")
        threading.Thread(target=handle_client, args=(client_socket, target_host, target_port)).start()


if __name__ == "__main__":
    start_proxy(PROXY_HOST, PROXY_PORT, TARGET_HOST, TARGET_PORT)
