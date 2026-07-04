import datetime
import os
import socket
import tempfile
import threading
import unittest
from unittest import mock

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID

import client
import server
from ca import build_cert
from security import (
    AES256_GCM_SIV_SUITE,
    CertificateValidationError,
    Session,
    validate_peer_certificate,
)


def make_certificates():
    ca_key = ed25519.Ed25519PrivateKey.generate()
    ca_cert = build_cert(
        "Test-CA",
        "Test-CA",
        ca_key.public_key(),
        ca_key,
        is_ca=True,
        path_length=0,
        days_valid=30,
    )
    server_key = ed25519.Ed25519PrivateKey.generate()
    server_cert = build_cert(
        "Sovereign-Chain-Server",
        "Test-CA",
        server_key.public_key(),
        ca_key,
        days_valid=7,
        san_names=["Sovereign-Chain-Server", "127.0.0.1"],
        extended_key_usages=[ExtendedKeyUsageOID.SERVER_AUTH],
    )
    client_key = ed25519.Ed25519PrivateKey.generate()
    client_cert = build_cert(
        "Sovereign-Chain-Client",
        "Test-CA",
        client_key.public_key(),
        ca_key,
        days_valid=7,
        san_names=["Sovereign-Chain-Client"],
        extended_key_usages=[ExtendedKeyUsageOID.CLIENT_AUTH],
    )
    return ca_cert, server_key, server_cert, client_key, client_cert


class CertificateValidationTests(unittest.TestCase):
    def setUp(self):
        self.ca, _, self.server_cert, _, self.client_cert = make_certificates()

    def test_validates_identity_and_role(self):
        self.assertIs(
            validate_peer_certificate(
                self.server_cert,
                self.ca,
                role="server",
                expected_identity="Sovereign-Chain-Server",
            ),
            self.server_cert,
        )

    def test_rejects_wrong_identity(self):
        with self.assertRaises(CertificateValidationError):
            validate_peer_certificate(
                self.server_cert,
                self.ca,
                role="server",
                expected_identity="other-service",
            )

    def test_rejects_wrong_extended_key_usage(self):
        with self.assertRaises(CertificateValidationError):
            validate_peer_certificate(self.client_cert, self.ca, role="server")

    def test_rejects_expired_certificate(self):
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=8)
        with self.assertRaises(CertificateValidationError):
            validate_peer_certificate(self.server_cert, self.ca, role="server", now=future)

    def test_rejects_revoked_certificate(self):
        ca_key = ed25519.Ed25519PrivateKey.generate()
        ca_cert = build_cert(
            "Revocation-CA",
            "Revocation-CA",
            ca_key.public_key(),
            ca_key,
            is_ca=True,
            path_length=0,
            days_valid=30,
        )
        server_key = ed25519.Ed25519PrivateKey.generate()
        server_cert = build_cert(
            "Sovereign-Chain-Server",
            "Revocation-CA",
            server_key.public_key(),
            ca_key,
            days_valid=7,
            san_names=["Sovereign-Chain-Server"],
            extended_key_usages=[ExtendedKeyUsageOID.SERVER_AUTH],
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(server_cert.serial_number)
            .revocation_date(now)
            .build()
        )
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(now - datetime.timedelta(minutes=1))
            .next_update(now + datetime.timedelta(days=1))
            .add_revoked_certificate(revoked)
            .sign(ca_key, algorithm=None)
        )
        path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False) as crl_file:
                path = crl_file.name
                crl_file.write(crl.public_bytes(serialization.Encoding.PEM))
            with mock.patch.dict(os.environ, {"SC_CRL_FILE": path}, clear=False):
                with self.assertRaises(CertificateValidationError):
                    validate_peer_certificate(server_cert, ca_cert, role="server")
        finally:
            if path:
                os.unlink(path)


class SessionTests(unittest.TestCase):
    def setUp(self):
        seed = b"s" * 64
        self.client = Session(b"a" * 32, b"b" * 32, seed, role="client")
        self.server = Session(b"b" * 32, b"a" * 32, seed, role="server")

    def test_bidirectional_key_evolution(self):
        for index in range(10):
            plaintext = f"message-{index}".encode()
            self.assertEqual(self.server.decrypt(self.client.encrypt(plaintext)), plaintext)
            self.assertEqual(self.client.decrypt(self.server.encrypt(plaintext)), plaintext)

    def test_tamper_does_not_advance_receive_chain(self):
        ciphertext = bytearray(self.client.encrypt(b"authenticated"))
        ciphertext[-1] ^= 1
        with self.assertRaises(Exception):
            self.server.decrypt(bytes(ciphertext))
        self.assertEqual(self.server.recv_seq, 1)

    def test_frame_type_is_authenticated(self):
        ciphertext = self.client.encrypt(
            b"control payload", frame_type=b"CONTROL"
        )
        with self.assertRaises(InvalidTag):
            self.server.decrypt(ciphertext, frame_type=b"DATA")
        self.assertEqual(self.server.recv_seq, 1)

    def test_session_identity_blocks_cross_session_replay(self):
        sender = Session(
            b"a" * 32,
            b"b" * 32,
            b"s" * 64,
            role="client",
            session_id=b"1" * 32,
        )
        wrong_session = Session(
            b"b" * 32,
            b"a" * 32,
            b"s" * 64,
            role="server",
            session_id=b"2" * 32,
        )
        with self.assertRaises(InvalidTag):
            wrong_session.decrypt(sender.encrypt(b"not reusable"))
        self.assertEqual(wrong_session.recv_seq, 1)

    def test_aes_256_gcm_siv_bidirectional_key_evolution(self):
        seed = b"s" * 64
        client_session = Session(
            b"a" * 32,
            b"b" * 32,
            seed,
            role="client",
            cipher_suite=AES256_GCM_SIV_SUITE,
        )
        server_session = Session(
            b"b" * 32,
            b"a" * 32,
            seed,
            role="server",
            cipher_suite=AES256_GCM_SIV_SUITE,
        )
        for index in range(10):
            plaintext = f"aes-message-{index}".encode()
            self.assertEqual(
                server_session.decrypt(client_session.encrypt(plaintext)),
                plaintext,
            )
            self.assertEqual(
                client_session.decrypt(server_session.encrypt(plaintext)),
                plaintext,
            )

    def test_sequence_assignment_is_atomic(self):
        sequences = []
        lock = threading.Lock()

        def encrypt_message(index):
            sequence, _ = self.client.encrypt_with_sequence(str(index).encode())
            with lock:
                sequences.append(sequence)

        workers = [threading.Thread(target=encrypt_message, args=(index,)) for index in range(50)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        self.assertEqual(sorted(sequences), list(range(1, 51)))

    def test_identical_messages_have_variable_ciphertext_lengths(self):
        environment = {
            "SC_MIN_PADDING_BYTES": "0",
            "SC_MAX_PADDING_BYTES": "32",
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            client_session = Session(
                b"a" * 32, b"b" * 32, b"s" * 64, role="client"
            )
            server_session = Session(
                b"b" * 32, b"a" * 32, b"s" * 64, role="server"
            )
        lengths = set()
        for _ in range(32):
            ciphertext = client_session.encrypt(b"hello")
            lengths.add(len(ciphertext))
            self.assertEqual(server_session.decrypt(ciphertext), b"hello")
        self.assertGreater(len(lengths), 1)

    def test_fixed_padding_length_is_accounted_for(self):
        environment = {
            "SC_MIN_PADDING_BYTES": "17",
            "SC_MAX_PADDING_BYTES": "17",
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            session = Session(b"a" * 32, b"b" * 32, b"s" * 64, role="client")
        ciphertext = session.encrypt(b"hello")
        self.assertEqual(len(ciphertext), 8 + 5 + 17 + 16)


class HandshakeIntegrationTests(unittest.TestCase):
    def _complete_handshake(self, cipher_suite):
        ca_cert, server_key, server_cert, client_key, client_cert = make_certificates()
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        outcome = {}
        client_aead = mock.Mock(wraps=client.create_aead)
        server_aead = mock.Mock(wraps=server.create_aead)

        def accept_connection():
            connection, address = listener.accept()
            try:
                outcome["session"] = server.server_handshake(
                    connection,
                    address,
                    server_key,
                    server_cert,
                    ca_cert,
                )
            except Exception as exc:
                outcome["error"] = exc
            finally:
                connection.close()

        client_hello_prefix = (
            b"CLIENTHELLO|" + client.PROTO_VER + b"|" + cipher_suite + b"|"
        )
        server_hello_prefix = (
            b"SERVERHELLO|" + client.PROTO_VER + b"|" + cipher_suite + b"|"
        )
        environment = {
            "SC_SERVER_NAME": "Sovereign-Chain-Server",
            "SC_ALLOWED_CLIENT_NAMES": "Sovereign-Chain-Client",
        }
        try:
            with mock.patch.dict(os.environ, environment, clear=False), \
                    mock.patch.multiple(
                        client,
                        CIPHER_SUITE=cipher_suite,
                        CLIENT_HELLO_PREFIX=client_hello_prefix,
                        SERVER_HELLO_PREFIX=server_hello_prefix,
                        create_aead=client_aead,
                    ), \
                    mock.patch.multiple(
                        server,
                        CIPHER_SUITE=cipher_suite,
                        CLIENT_HELLO_PREFIX=client_hello_prefix,
                        SERVER_HELLO_PREFIX=server_hello_prefix,
                        create_aead=server_aead,
                    ), \
                    mock.patch.object(client, "load_priv", return_value=client_key), \
                    mock.patch.object(client, "load_cert", return_value=client_cert), \
                    mock.patch.object(client, "load_ca_cert", return_value=ca_cert):
                worker = threading.Thread(target=accept_connection)
                worker.start()
                client_session, client_socket = client.client_handshake(
                    "127.0.0.1", port
                )
                client_socket.close()
                worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
            self.assertNotIn("error", outcome)
            return client_session, outcome["session"], client_aead, server_aead
        finally:
            listener.close()

    def test_server_rejects_unbound_legacy_client_hello(self):
        ca_cert, server_key, server_cert, _, _ = make_certificates()
        server_socket, client_socket = socket.socketpair()
        try:
            client_socket.sendall(server.pack(b"CLIENTHELLO|" + os.urandom(48)))
            with self.assertRaises(server.ProtocolError):
                server.server_handshake(
                    server_socket,
                    ("local", 0),
                    server_key,
                    server_cert,
                    ca_cert,
                )
        finally:
            server_socket.close()
            client_socket.close()

    def test_client_and_server_complete_sc_ee_3_handshake(self):
        client_session, server_session, client_aead, server_aead = (
            self._complete_handshake(client.CIPHER_SUITE)
        )
        self.assertEqual(client_session.send_seq, 1)
        self.assertEqual(server_session.recv_seq, 1)
        self.assertEqual(client_aead.call_args.args[1], client.CIPHER_SUITE)
        self.assertEqual(server_aead.call_args.args[1], server.CIPHER_SUITE)

    def test_aes_suite_protects_seed_stage_and_session(self):
        client_session, server_session, client_aead, server_aead = (
            self._complete_handshake(AES256_GCM_SIV_SUITE)
        )
        self.assertEqual(client_session.cipher_suite, AES256_GCM_SIV_SUITE)
        self.assertEqual(server_session.cipher_suite, AES256_GCM_SIV_SUITE)
        client_aead.assert_called_once()
        server_aead.assert_called_once()
        self.assertEqual(client_aead.call_args.args[1], AES256_GCM_SIV_SUITE)
        self.assertEqual(server_aead.call_args.args[1], AES256_GCM_SIV_SUITE)


if __name__ == "__main__":
    unittest.main()
