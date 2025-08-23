#!/usr/bin/env python3
"""
server_proxy.py - 智能代理（支持天启御链协议和普通透明转发）

行为：
- 探测入站连接是否为 SC 协议（长度前缀 + "CLIENTHELLO|"）
- 如果是：调用 server.handle_conn(...) 完成握手，取得 Session，之后把解密后的 Minecraft 流量转发到 MC_HOST:MC_PORT，
        并把 MC 返回的数据加密后发回客户端。
- 如果不是：做透明 TCP 代理（直接把连接桥接到 MC_HOST:MC_PORT）。

注意：
- 依赖 `server.py` 中导出的： Session, handle_conn, load_pem_priv, load_pem_cert, recv_frame, pack
- 要保证 handle_conn 在握手完成后**返回**一个 Session（或 (Session, ...)），否则代理无法继续转发加密流量。
"""

import socket
import struct
import threading
import time

from server import Session, handle_conn, load_pem_priv, load_pem_cert, recv_frame, pack

MC_HOST = "xrsl.club"
MC_PORT = 25565  # 真正的 Minecraft 服务地址（可改为本机 127.0.0.1:25565）
PROXY_HOST = "0.0.0.0"
PROXY_PORT = 25566  # 这个代理监听端口（客户端应连接到此端口）

# 最大允许的 frame 长度（与 server.recv_frame 中一致）
MAX_FRAME = 50_000_000


def is_sc_protocol(sock: socket.socket, peek_max=64, timeout=0.5) -> bool:
    """
    通过 MSG_PEEK 检测入站连接是否为 SC 协议：
    - 先 peek 4 字节（大端 uint32 长度）
    - 若长度在合理范围内，再 peek 少量数据检查 payload 是否以 b'CLIENTHELLO|' 开头
    返回 True 表示很可能是 SC 协议。
    """
    try:
        prev_to = sock.gettimeout()
    except Exception:
        prev_to = None
    try:
        sock.settimeout(timeout)
        hdr = sock.recv(4, socket.MSG_PEEK)
        if len(hdr) < 4:
            return False
        (l,) = struct.unpack(">I", hdr)
        if l <= 0 or l > MAX_FRAME:
            return False
        # peek 4 + min(l, peek_max) bytes to inspect payload start
        want = 4 + min(l, peek_max)
        data = sock.recv(want, socket.MSG_PEEK)
        if len(data) < 5:
            return False
        payload = data[4:]
        return payload.startswith(b"CLIENTHELLO|")
    except Exception:
        return False
    finally:
        try:
            sock.settimeout(prev_to)
        except Exception:
            sock.settimeout(None)


def forward_plain(a: socket.socket, b: socket.socket):
    """透明双向转发：a <-> b"""
    def _f(src, dst, name):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                src.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass

    t1 = threading.Thread(target=_f, args=(a, b, "A->B"), daemon=True)
    t2 = threading.Thread(target=_f, args=(b, a, "B->A"), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()
    a.close(); b.close()


def forward_encrypted(client_sock: socket.socket, mc_sock: socket.socket, sess: Session):
    """
    双向转发：client <-> MC，但 client <-> proxy 使用加密帧（DATA|<ct>），
    client 发来的 DATA 解密后发给 mc_sock；mc_sock 的回复加密后用 pack 发送回 client。
    """
    stopped = threading.Event()

    def c2s():
        try:
            while not stopped.is_set():
                # recv_frame 从 client_sock 读取长度前缀帧
                frm = recv_frame(client_sock)
                if not frm.startswith(b"DATA|"):
                    # 忽略非 DATA 帧
                    continue
                ct = frm.split(b"|", 1)[1]
                try:
                    pt = sess.decrypt(ct)
                except Exception as e:
                    # 解密错误 -> 断开
                    print("[proxy] decrypt error from client:", e)
                    break
                if not pt:
                    continue
                mc_sock.sendall(pt)
        except Exception as e:
            # 读取错误（client 关闭/协议错误等）
            # print("[proxy] c2s error:", e)
            pass
        finally:
            stopped.set()
            try:
                mc_sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                client_sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass

    def s2c():
        try:
            while not stopped.is_set():
                data = mc_sock.recv(4096)
                if not data:
                    break
                try:
                    ct = sess.encrypt(data)
                except Exception as e:
                    print("[proxy] encrypt error to client:", e)
                    break
                client_sock.sendall(pack(b"DATA|" + ct))
        except Exception:
            pass
        finally:
            stopped.set()
            try:
                mc_sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                client_sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass

    t1 = threading.Thread(target=c2s, daemon=True)
    t2 = threading.Thread(target=s2c, daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()
    client_sock.close(); mc_sock.close()


def handle_proxy(conn: socket.socket, addr, server_priv, server_cert, ca_cert):
    """
    单个入站连接处理：
    - 探测协议类型
    - 若为 SC 协议：调用 handle_conn 完成握手并期望得到一个 Session（参见 server.handle_conn 的修改）
                     随后连接 MC 服务并启动 forward_encrypted
    - 若为其他：直接做透明代理 forward_plain
    """
    print("incoming from", addr)
    try:
        if is_sc_protocol(conn):
            print("[proxy] detected SC protocol from", addr)
            # 调用 server.handle_conn 完成握手 —— 期望返回一个 Session（或者 (Session, ...)）
            try:
                res = handle_conn(conn, addr, server_priv, server_cert, ca_cert)
            except Exception as e:
                print("[proxy] handle_conn raised:", e)
                conn.close()
                return

            # handle_conn 可能返回 Session 或 (Session, ...)
            sess = None
            if isinstance(res, Session):
                sess = res
            elif isinstance(res, tuple) and isinstance(res[0], Session):
                sess = res[0]
            elif res is None:
                # 如果 handle_conn 已经完整处理并关闭连接（未返回 Session），我们结束
                print("[proxy] handle_conn did not return a Session; assuming it handled the connection.")
                return
            else:
                # 未知返回类型：尝试继续，但先关闭
                print("[proxy] unexpected handle_conn return:", type(res))
                conn.close()
                return

            # 连接真正的 Minecraft 服务
            try:
                mc_sock = socket.create_connection((MC_HOST, MC_PORT))
            except Exception as e:
                print("[proxy] cannot connect to MC server", MC_HOST, MC_PORT, ":", e)
                conn.close()
                return

            print("[proxy] forwarding encrypted <-> mc", addr, "->", (MC_HOST, MC_PORT))
            forward_encrypted(conn, mc_sock, sess)

        else:
            # 不是 SC 协议 -> 透明 TCP 代理转发到 MC 服务
            print("[proxy] non-SC protocol (fallback transparent) from", addr)
            try:
                mc_sock = socket.create_connection((MC_HOST, MC_PORT))
            except Exception as e:
                print("[proxy] cannot connect to MC server for transparent forwarding:", e)
                conn.close()
                return
            forward_plain(conn, mc_sock)

    except Exception as e:
        print("[proxy] error handling connection:", e)
    finally:
        try:
            conn.close()
        except Exception:
            pass
        print("[proxy] closed connection from", addr)


def main():
    server_priv = load_pem_priv("server_key.pem")
    server_cert = load_pem_cert("server_cert.pem")
    ca_cert = load_pem_cert("ca_cert.pem")

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((PROXY_HOST, PROXY_PORT))
    s.listen(128)
    print("proxy listening", PROXY_HOST, PROXY_PORT)
    try:
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_proxy, args=(conn, addr, server_priv, server_cert, ca_cert), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("bye")
    finally:
        s.close()


if __name__ == "__main__":
    main()
