import os
import socket
import tempfile
import threading
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization

from sovereign_chain.credentials import CLIENT_NAME, SERVER_NAME, server_credentials
from sovereign_chain.pki import initialize
from sovereign_chain.proxy import client_proxy_handler, server_proxy_handler
from sovereign_chain.service import TCPService


@contextmanager
def running(handler, limit=4):
    service = TCPService(("127.0.0.1", 0), handler, limit)
    thread = threading.Thread(target=service.serve, daemon=True)
    thread.start()
    try:
        if not service.ready.wait(5):
            raise AssertionError("listener did not start")
        yield service
    finally:
        service.stop()
        thread.join(8)
        if thread.is_alive():
            raise AssertionError("listener failed to stop")


def read_to_eof(sock):
    chunks = []
    while data := sock.recv(65536):
        chunks.append(data)
    return b"".join(chunks)


class ListenerTests(unittest.TestCase):
    def test_idle_listener_stops(self):
        with running(lambda *args: None):
            pass

    def test_active_connection_is_closed_and_capacity_is_bounded(self):
        entered = threading.Event()
        calls = []

        def handle(service, sock, address):
            calls.append(address)
            entered.set()
            sock.recv(1)

        with ExitStack() as clients:
            with running(handle, limit=1) as service:
                first = clients.enter_context(
                    socket.create_connection(service.address, timeout=3)
                )
                self.assertTrue(entered.wait(3))
                with socket.create_connection(service.address, timeout=3) as second:
                    self.assertEqual(second.recv(1), b"")
                self.assertEqual(len(calls), 1)
            self.assertEqual(first.recv(1), b"")


class PKIAndRelayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        folder = tempfile.TemporaryDirectory()
        cls.addClassCleanup(folder.cleanup)
        cls.pki = Path(folder.name) / "pki"
        clean_env = {k: v for k, v in os.environ.items() if not k.startswith("SC_")}
        clean_env["SC_PKI_DIR"] = str(cls.pki)
        env = patch.dict(os.environ, clean_env, clear=True)
        env.start()
        cls.addClassCleanup(env.stop)
        initialize(cls.pki, b"temporary test password", SERVER_NAME, CLIENT_NAME)

    def test_role_keys_are_isolated_and_authority_keys_are_encrypted(self):
        for role in ("client", "server"):
            names = {p.name for p in (self.pki / role).iterdir()}
            self.assertEqual(
                names, {"ca_cert.pem", f"{role}_key.pem", f"{role}_cert.pem"}
            )
        for key in (self.pki / "authority").glob("*_key.pem"):
            with self.assertRaises(TypeError):
                serialization.load_pem_private_key(key.read_bytes(), password=None)
        with self.assertRaises(FileExistsError):
            initialize(self.pki, b"different test password", SERVER_NAME, CLIENT_NAME)

    def test_half_close_preserves_response_through_both_proxies(self):
        # This target deliberately waits for EOF before sending its entire response.
        def target_handler(service, sock, peer):
            sock.sendall(b"reply:" + read_to_eof(sock))

        data = bytes(range(256)) * 512
        with ExitStack() as stack:
            target = stack.enter_context(running(target_handler))
            receiver = stack.enter_context(
                running(server_proxy_handler(target.address, server_credentials()))
            )
            sender = stack.enter_context(
                running(client_proxy_handler(receiver.address))
            )
            with socket.create_connection(sender.address, timeout=5) as app:
                app.sendall(data)
                app.shutdown(socket.SHUT_WR)
                self.assertEqual(read_to_eof(app), b"reply:" + data)

    def test_reverse_half_close_keeps_upload_open(self):
        result = []
        finished = threading.Event()

        def target_handler(service, sock, peer):
            sock.sendall(b"ready")
            sock.shutdown(socket.SHUT_WR)
            result.append(read_to_eof(sock))
            finished.set()

        with ExitStack() as stack:
            target = stack.enter_context(running(target_handler))
            receiver = stack.enter_context(
                running(server_proxy_handler(target.address, server_credentials()))
            )
            sender = stack.enter_context(
                running(client_proxy_handler(receiver.address))
            )
            with socket.create_connection(sender.address, timeout=5) as app:
                self.assertEqual(read_to_eof(app), b"ready")
                app.sendall(b"final upload")
                app.shutdown(socket.SHUT_WR)
                self.assertTrue(finished.wait(3))
                self.assertEqual(result, [b"final upload"])
