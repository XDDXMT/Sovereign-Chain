"""Regression checks for the documented issuer profile, trust rotation and proxy admission."""

import datetime
import io
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from test_runtime import read_to_eof, running

from sovereign_chain.__main__ import echo_handler, main
from sovereign_chain.client import client_handshake
from sovereign_chain.credentials import CLIENT_NAME, SERVER_NAME, CredentialStore
from sovereign_chain.pki import build_cert, initialize
from sovereign_chain.proxy import Endpoint, client_proxy_handler, server_proxy_handler
from sovereign_chain.security import Session
from sovereign_chain.service import Timeouts
from sovereign_chain.trust import (
    CertificateValidationError,
    parse_crl,
    public_key_id,
    require_identity,
    validate_ca_certificate,
    validate_peer_certificate,
)
from sovereign_chain.wire import (
    DATA,
    FIN,
    encode_record,
    receive_record,
    recv_exact,
    send_record,
)


def wait_for(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.04)
    raise AssertionError("condition did not become true")


class TrustProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = ed25519.Ed25519PrivateKey.generate()
        cls.ca = build_cert(
            "CA", "CA", cls.key.public_key(), cls.key, is_ca=True, path_length=0
        )

    def leaf(self, names, extra=None):
        now = datetime.datetime.now(datetime.timezone.utc)
        b = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unit")]))
            .issuer_name(self.ca.subject)
            .public_key(ed25519.Ed25519PrivateKey.generate().public_key())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .serial_number(x509.random_serial_number())
            .add_extension(x509.BasicConstraints(False, None), True)
            .add_extension(
                x509.KeyUsage(
                    True, False, False, False, False, False, False, False, False
                ),
                True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False
            )
            .add_extension(x509.SubjectAlternativeName(names), False)
        )
        if extra:
            b = b.add_extension(extra, True)
        return b.sign(self.key, None)

    def crl(self, extra=None, ca=None):
        now = datetime.datetime.now(datetime.timezone.utc)
        b = (
            x509.CertificateRevocationListBuilder()
            .issuer_name((ca or self.ca).subject)
            .last_update(now - datetime.timedelta(minutes=1))
            .next_update(now + datetime.timedelta(days=1))
        )
        if extra:
            b = b.add_extension(extra, True)
        return b.sign(self.key, None).public_bytes(serialization.Encoding.DER)

    def test_critical_extension_policy_and_typed_san(self):
        good = self.leaf([x509.DNSName("workstation")])
        validate_peer_certificate(
            good, self.ca, "client", "WORKSTATION", revocations=None
        )
        unknown = x509.UnrecognizedExtension(
            x509.ObjectIdentifier("1.3.6.1.4.1.55555.1"), b"test"
        )
        with self.assertRaisesRegex(CertificateValidationError, "critical extension"):
            validate_peer_certificate(
                self.leaf([x509.DNSName("unit")], unknown),
                self.ca,
                "client",
                revocations=None,
            )
        dns_only = self.leaf([x509.DNSName("127.0.0.1")])
        with self.assertRaises(CertificateValidationError):
            require_identity(dns_only, ["127.0.0.1"])

    def test_retired_key_is_identified_by_spki(self):
        with patch(
            "sovereign_chain.trust.RETIRED_KEYS", {public_key_id(self.key.public_key())}
        ):
            with self.assertRaisesRegex(CertificateValidationError, "retired"):
                validate_ca_certificate(self.ca)

    def test_only_complete_direct_crls_are_accepted(self):
        self.assertEqual(parse_crl(self.crl(), self.ca).serials, frozenset())
        for ext in (
            x509.DeltaCRLIndicator(1),
            x509.IssuingDistributionPoint(None, None, True, False, None, False, False),
        ):
            with (
                self.subTest(ext=ext),
                self.assertRaisesRegex(CertificateValidationError, "scope"),
            ):
                parse_crl(self.crl(ext), self.ca)

    def test_crl_sign_permission_required(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        ca = (
            x509.CertificateBuilder()
            .subject_name(self.ca.subject)
            .issuer_name(self.ca.subject)
            .public_key(self.key.public_key())
            .serial_number(3)
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(True, 0), True)
            .add_extension(
                x509.KeyUsage(
                    True, False, False, False, False, True, False, False, False
                ),
                True,
            )
            .sign(self.key, None)
        )
        with self.assertRaisesRegex(CertificateValidationError, "cannot sign CRLs"):
            parse_crl(self.crl(ca=ca), ca)


class StreamTests(unittest.TestCase):
    def test_fragmented_header_and_coalesced_records_keep_sequence(self):
        sender = Session(b"a" * 32, b"b" * 32, b"s" * 64)
        receiver = Session(b"b" * 32, b"a" * 32, b"s" * 64, role="server")
        first = encode_record(sender, b"one")
        second = encode_record(sender, b"two")
        local = Mock()
        local.recv.side_effect = [first[:2], first[2:9], first[9:] + second]
        stream = Endpoint(local, receiver)
        for tick in (1, 2):
            self.assertIsNone(stream.read(tick, Timeouts()))
            self.assertEqual(receiver.recv_seq, 1)
        self.assertEqual(stream.read(3, Timeouts()), (DATA, b"one"))
        self.assertEqual(stream.buffered(3, Timeouts()), (DATA, b"two"))
        self.assertEqual(receiver.recv_seq, 3)
        self.assertFalse(stream.buffer)

    def test_plaintext_mode_refuses_public_listen_address(self):
        with patch("sys.stderr", new_callable=io.StringIO) as output:
            self.assertEqual(
                main(
                    ["client-proxy", "--trusted-loopback", "--listen-host", "0.0.0.0"]
                ),
                1,
            )
        self.assertIn("loopback listen address", output.getvalue())


class DeploymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temp.cleanup)
        env = patch.dict(
            os.environ,
            {k: v for k, v in os.environ.items() if not k.startswith("SC_")},
            clear=True,
        )
        env.start()
        cls.addClassCleanup(env.stop)
        cls.primary = initialize(
            Path(temp.name) / "primary", b"test authority", SERVER_NAME, CLIENT_NAME
        )
        cls.edge = initialize(
            Path(temp.name) / "edge", b"test authority", SERVER_NAME, "workstation-a"
        )
        os.environ["SC_PKI_DIR"] = str(cls.primary)

    def new_store(self, role, directory):
        store = CredentialStore(role, ingress_dir=directory)
        store.refresh()
        store.current()
        return store

    def test_running_store_refuses_crl_rollback_and_recovers(self):
        issuer = x509.load_pem_x509_certificate(
            (self.primary / "server/ca_cert.pem").read_bytes()
        )
        signer = serialization.load_pem_private_key(
            (self.primary / "authority/intermediate_ca_key.pem").read_bytes(),
            b"test authority",
        )
        now = datetime.datetime.now(datetime.timezone.utc)

        def numbered_crl(number):
            return (
                x509.CertificateRevocationListBuilder()
                .issuer_name(issuer.subject)
                .last_update(now - datetime.timedelta(minutes=1))
                .next_update(now + datetime.timedelta(days=1))
                .add_extension(x509.CRLNumber(number), critical=False)
                .sign(signer, None)
                .public_bytes(serialization.Encoding.PEM)
            )

        with tempfile.TemporaryDirectory() as tmp:
            crl = Path(tmp) / "current.crl"

            def publish(number):
                staged = crl.with_suffix(".new")
                staged.write_bytes(numbered_crl(number))
                staged.replace(crl)

            publish(2)
            with patch.dict(
                os.environ,
                {"SC_INGRESS_CRL_FILE": str(crl), "SC_INGRESS_REQUIRE_CRL": "true"},
            ):
                store = self.new_store("server", self.primary)
                self.assertEqual(store.current().revocations.number, 2)
                publish(1)
                self.assertTrue(store.refresh())
                self.assertFalse(store.available)
                publish(3)
                self.assertTrue(store.refresh())
                self.assertEqual(store.current().revocations.number, 3)

    def test_authenticated_ingress_transfers_binary_and_preserves_fin(self):
        def reply(service, sock, peer):
            sock.sendall(b"received:" + read_to_eof(sock))

        ingress = self.new_store("server", self.edge)
        caller = self.new_store("client", self.edge)
        upstream = self.new_store("client", self.primary)
        receiver = self.new_store("server", self.primary)
        data = bytes(range(256)) * 1200
        with ExitStack() as stack:
            target = stack.enter_context(running(reply))
            out = stack.enter_context(
                running(
                    server_proxy_handler(target.address, receiver), stores=(receiver,)
                )
            )
            gateway = stack.enter_context(
                running(
                    client_proxy_handler(
                        out.address,
                        ingress=ingress,
                        caller="workstation-a",
                        outbound=upstream,
                    ),
                    stores=(ingress, upstream),
                )
            )
            session, stream = client_handshake(
                *gateway.address, identity=caller.current()
            )
            with stream:
                stream.settimeout(4)
                send_record(stream, session, data)
                send_record(stream, session, b"", FIN)
                result = bytearray()
                while True:
                    kind, part = receive_record(stream, session)
                    if kind == FIN:
                        break
                    result.extend(part)
                self.assertEqual(result, b"received:" + data)

    def test_ingress_rejects_other_named_caller_before_upstream_connect(self):
        used = threading.Event()
        with self.assertRaises(ValueError):
            client_proxy_handler(("127.0.0.1", 0))
        ingress = self.new_store("server", self.edge)
        caller = self.new_store("client", self.edge)
        with running(lambda svc, sock, peer: used.set()) as target:
            with running(
                client_proxy_handler(
                    target.address, ingress=ingress, caller="another-workstation"
                )
            ) as gateway:
                with self.assertRaises((ConnectionError, EOFError, OSError)):
                    client_handshake(*gateway.address, identity=caller.current())
            self.assertFalse(used.is_set())

    def test_rotation_retires_existing_sessions_and_recovers_after_incomplete_update(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            live = Path(tmp) / "live"
            shutil.copytree(self.primary / "server", live / "server")
            store = self.new_store("server", live)
            old_client = self.new_store("client", self.primary)
            newer_client = self.new_store("client", self.edge)
            with patch.dict(
                os.environ, {"SC_ALLOWED_CLIENT_NAMES": CLIENT_NAME + ",workstation-a"}
            ):
                with running(echo_handler(store), stores=(store,)) as srv:
                    old, stream = client_handshake(
                        *srv.address, identity=old_client.current()
                    )
                    with stream:
                        stream.settimeout(5)
                        send_record(stream, old, b"before")
                        self.assertEqual(
                            receive_record(stream, old), (DATA, b"echo: before")
                        )
                        (live / "server" / "ca_cert.pem").unlink()
                        wait_for(lambda: not store.available)
                        try:
                            end = stream.recv(1)
                        except (ConnectionResetError, ConnectionAbortedError):
                            end = b""
                        self.assertEqual(end, b"")
                    for file in (self.edge / "server").iterdir():
                        dst = live / "server" / file.name
                        staging = dst.with_suffix(".new")
                        staging.write_bytes(file.read_bytes())
                        staging.replace(dst)
                    wait_for(lambda: store.available)
                    with self.assertRaises(CertificateValidationError):
                        client_handshake(*srv.address, identity=old_client.current())
                    new, stream = client_handshake(
                        *srv.address, identity=newer_client.current()
                    )
                    with stream:
                        send_record(stream, new, b"after")
                        self.assertEqual(
                            receive_record(stream, new), (DATA, b"echo: after")
                        )

    def test_idle_and_half_closed_connections_release_capacity(self):
        receiver = self.new_store("server", self.primary)
        release_target = threading.Event()
        with ExitStack() as stack:
            target = stack.enter_context(
                running(lambda svc, sock, peer: release_target.wait(4))
            )
            try:
                for half_close in (False, True):
                    policy = Timeouts(
                        idle=3 if half_close else 0.25, drain=0.25, write=1, lifetime=5
                    )
                    with (
                        self.subTest(half_close=half_close),
                        running(
                            server_proxy_handler(target.address, receiver),
                            limit=1,
                            policy=policy,
                        ) as srv,
                    ):
                        session, stream = client_handshake(*srv.address)
                        with stream:
                            stream.settimeout(2)
                            if half_close:
                                send_record(stream, session, b"", FIN)
                            try:
                                end = stream.recv(1)
                            except (ConnectionAbortedError, ConnectionResetError):
                                end = b""
                            self.assertEqual(end, b"")
                        wait_for(lambda: not srv.workers)
                        _, replacement = client_handshake(*srv.address)
                        replacement.close()
            finally:
                release_target.set()

    def test_stopping_active_proxy_does_not_signal_successful_eof(self):
        store = self.new_store("server", self.primary)
        with running(echo_handler(store), stores=(store,)) as remote:
            with running(
                client_proxy_handler(remote.address, trusted_loopback=True)
            ) as local:
                with socket.create_connection(local.address, timeout=3) as app:
                    app.sendall(b"alive")
                    self.assertEqual(recv_exact(app, 11), b"echo: alive")
                    local.stop()
                    with self.assertRaises(
                        (ConnectionResetError, ConnectionAbortedError)
                    ):
                        app.recv(1)

    def test_remote_close_without_fin_aborts_plain_tcp(self):
        creds = self.new_store("server", self.primary).current()

        def close_after_data(service, sock, peer):
            from sovereign_chain.server import server_handshake

            session = server_handshake(sock, peer, creds.key, creds.cert, creds.anchor)
            send_record(sock, session, b"prefix")
            receive_record(sock, session)  # Wait until the app has consumed the prefix.

        with running(close_after_data) as remote:
            with running(
                client_proxy_handler(remote.address, trusted_loopback=True)
            ) as gateway:
                with socket.create_connection(gateway.address, timeout=3) as plain:
                    self.assertEqual(recv_exact(plain, 6), b"prefix")
                    plain.sendall(b"ack")
                    with self.assertRaises(
                        (ConnectionResetError, ConnectionAbortedError)
                    ):
                        plain.recv(1)
