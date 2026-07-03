#!/usr/bin/env python3
"""Decrypt Sovereign-Chain traffic and relay it to a plain TCP service."""

import logging
import os
import socket
import struct
import threading

from security import validate_peer_certificate, verify_private_key_matches_certificate
from server import (
    load_ca_cert,
    load_pem_cert,
    load_pem_priv,
    pack,
    recv_frame,
    server_handshake,
)


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


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


class ServerProxy:
    def __init__(
        self,
        listen_host="0.0.0.0",
        listen_port=25558,
        target_host="127.0.0.1",
        target_port=3389,
        max_connections=100,
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.running = False
        self._connections = threading.Semaphore(max_connections)
        self._server_socket = None

    def handle_proxy_connection(self, client_sock, client_addr, credentials):
        target_sock = None
        with self._connections:
            try:
                server_priv, server_cert, ca_cert = credentials
                session = server_handshake(
                    client_sock,
                    client_addr,
                    server_priv,
                    server_cert,
                    ca_cert,
                )
                target_sock = socket.create_connection(
                    (self.target_host, self.target_port),
                    timeout=10,
                )
                target_sock.settimeout(None)
                logger.info(
                    "Secure proxy connected %s to %s:%s",
                    client_addr,
                    self.target_host,
                    self.target_port,
                )

                workers = (
                    threading.Thread(
                        target=self.forward_client_to_target,
                        args=(client_sock, target_sock, session, client_addr),
                        daemon=True,
                    ),
                    threading.Thread(
                        target=self.forward_target_to_client,
                        args=(client_sock, target_sock, session, client_addr),
                        daemon=True,
                    ),
                )
                for worker in workers:
                    worker.start()
                for worker in workers:
                    worker.join()
            except Exception as exc:
                logger.error("Proxy connection %s failed: %s", client_addr, exc)
            finally:
                close_socket(target_sock)
                close_socket(client_sock)
                logger.info("Proxy connection %s closed", client_addr)

    @staticmethod
    def forward_client_to_target(client_sock, target_sock, session, client_addr):
        try:
            while True:
                frame = recv_frame(client_sock)
                if not frame.startswith(b"DATA") or len(frame) < 12:
                    raise ValueError("invalid encrypted application frame")
                sequence = struct.unpack(">Q", frame[4:12])[0]
                target_sock.sendall(
                    session.decrypt_with_sequence(sequence, frame[12:])
                )
        except (ConnectionError, OSError, ValueError) as exc:
            logger.info("Client-to-target relay ended for %s: %s", client_addr, exc)
        finally:
            close_socket(target_sock)
            close_socket(client_sock)

    @staticmethod
    def forward_target_to_client(client_sock, target_sock, session, client_addr):
        try:
            while True:
                data = target_sock.recv(65536)
                if not data:
                    break
                sequence, ciphertext = session.encrypt_with_sequence(data)
                client_sock.sendall(
                    pack(b"DATA" + struct.pack(">Q", sequence) + ciphertext)
                )
        except (ConnectionError, OSError, ValueError) as exc:
            logger.info("Target-to-client relay ended for %s: %s", client_addr, exc)
        finally:
            close_socket(client_sock)
            close_socket(target_sock)

    def start(self, credentials):
        self.running = True
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.listen_host, self.listen_port))
        self._server_socket.listen(64)
        logger.info("Server proxy listening on %s:%s", self.listen_host, self.listen_port)
        logger.info("Forwarding to %s:%s", self.target_host, self.target_port)

        try:
            while self.running:
                client_sock, client_addr = self._server_socket.accept()
                threading.Thread(
                    target=self.handle_proxy_connection,
                    args=(client_sock, client_addr, credentials),
                    daemon=True,
                ).start()
        finally:
            close_socket(self._server_socket)

    def stop(self):
        self.running = False
        close_socket(self._server_socket)


def load_credentials():
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
    return server_priv, server_cert, ca_cert


def main():
    listen_host = os.getenv("SC_PROXY_LISTEN_HOST", "0.0.0.0")
    listen_port = int(os.getenv("SC_PROXY_LISTEN_PORT", "25558"))
    target_host = os.getenv("SC_PROXY_TARGET_HOST", "10.0.0.131")
    target_port = int(os.getenv("SC_PROXY_TARGET_PORT", "3389"))

    try:
        credentials = load_credentials()
        proxy = ServerProxy(listen_host, listen_port, target_host, target_port)
        proxy.start(credentials)
    except KeyboardInterrupt:
        logger.info("Server proxy shutting down")
    except Exception as exc:
        logger.error("Server proxy failed: %s", exc)


if __name__ == "__main__":
    main()
