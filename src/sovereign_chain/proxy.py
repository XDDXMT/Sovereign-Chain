"""One bounded, backpressured bidirectional pump per authenticated TCP connection."""

import ipaddress
import select
import socket
import time

from .client import authenticate_client
from .credentials import CredentialStore
from .security import (
    MAX_ACCEPTED_PADDING,
    MAX_FRAME_SIZE,
    PADDING_HEADER,
    RECORD_HEADER_SIZE,
)
from .server import server_handshake
from .service import abort_socket, shutdown
from .wire import (
    DATA,
    FIN,
    HANDSHAKE_TIMEOUT,
    LENGTH,
    ProtocolError,
    decode_record,
    encode_record,
)

CHUNK = 65536
# An incoming record may need slightly more padding when sealed for a different leg.
MAX_CLEAR = (
    MAX_FRAME_SIZE
    - RECORD_HEADER_SIZE
    - PADDING_HEADER.size
    - 16
    - MAX_ACCEPTED_PADDING
)


def loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Endpoint:
    """At most one partial frame in and one bounded batch out per socket."""

    def __init__(self, sock, session):
        self.sock = sock
        self.session = session
        self.buffer = bytearray()
        self.cursor = 0
        self.body_length = None
        self.pending = memoryview(b"")
        self.read_end = False
        self.finish_write = False
        self.read_deadline = self.write_deadline = float("inf")
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setblocking(False)

    def read(self, now, policy):
        if self.session is None:
            chunk = self.sock.recv(CHUNK)
            return (DATA, chunk) if chunk else (FIN, b"")
        chunk = self.sock.recv(2 * CHUNK)
        if not chunk:
            raise ProtocolError("secure stream ended before authenticated FIN")
        if not self.buffer and len(chunk) >= LENGTH.size:
            (size,) = LENGTH.unpack_from(chunk)
            if not 12 <= size <= MAX_FRAME_SIZE:
                raise ProtocolError("invalid application record size")
            if len(chunk) == LENGTH.size + size:
                return decode_record(self.session, memoryview(chunk)[LENGTH.size :])
        if self.read_deadline == float("inf"):
            self.read_deadline = now + policy.idle
        self.buffer.extend(chunk)
        return self.buffered(now, policy)

    def buffered(self, now, policy):
        """Parse one record from bounded read-ahead without another socket round trip."""
        available = len(self.buffer) - self.cursor
        if self.body_length is None:
            if available < LENGTH.size:
                return None
            (self.body_length,) = LENGTH.unpack_from(self.buffer, self.cursor)
            if not 12 <= self.body_length <= MAX_FRAME_SIZE:
                raise ProtocolError("invalid application record size")
            self.cursor += LENGTH.size
        end = self.cursor + self.body_length
        if len(self.buffer) < end:
            return None
        record = decode_record(
            self.session, bytes(memoryview(self.buffer)[self.cursor : end])
        )
        self.cursor = end
        self.body_length = None
        if end == len(self.buffer) or end >= CHUNK:
            del self.buffer[:end]
            self.cursor = 0
        self.read_deadline = now + policy.idle if self.buffer else float("inf")
        return record

    def queue(self, kind, data, now, policy):
        if self.session is not None:
            if len(data) <= MAX_CLEAR:
                data = encode_record(self.session, data, kind)
            else:
                data = b"".join(
                    encode_record(self.session, data[i : i + MAX_CLEAR])
                    for i in range(0, len(data), MAX_CLEAR)
                )
        self.finish_write = kind == FIN
        self.pending = memoryview(data)
        if self.pending:
            self.write_deadline = now + policy.write
        else:
            self._written()

    def flush(self):
        count = self.sock.send(self.pending)
        if not count:
            raise ConnectionError("peer stopped receiving")
        self.pending = self.pending[count:]
        if not self.pending:
            self._written()

    def _written(self):
        self.write_deadline = float("inf")
        if self.finish_write:
            shutdown(self.sock, socket.SHUT_WR)
            self.finish_write = False


def relay(connection, first, second):
    """A clean EOF is propagated per direction only after verified FIN on an SC leg."""
    policy = connection.policy
    peers = {first.sock: (first, second), second.sock: (second, first)}
    last_progress = time.monotonic()
    drain_deadline = float("inf")

    def deliver(src, dst, record, now):
        nonlocal last_progress, drain_deadline
        kind, data = record
        if kind == FIN:
            if len(src.buffer) > src.cursor:
                raise ProtocolError("unexpected buffered data after FIN")
            src.read_end = True
            drain_deadline = min(drain_deadline, now + policy.drain)
        dst.queue(kind, data, now, policy)
        # Usually the socket has capacity already. Only poll for write readiness
        # if this immediate, nonblocking send did not drain the batch.
        if dst.pending:
            try:
                dst.flush()
            except BlockingIOError:
                pass
        last_progress = now

    try:
        while True:
            now = time.monotonic()
            deadline = min(
                connection.end,
                last_progress + policy.idle,
                drain_deadline,
                first.read_deadline,
                second.read_deadline,
                first.write_deadline,
                second.write_deadline,
            )
            if now >= deadline:
                raise TimeoutError(
                    "relay idle, write, drain or session deadline reached"
                )
            processed = False
            for src, dst in peers.values():
                if src.buffer and not src.read_end and not dst.pending:
                    record = src.buffered(now, policy)
                    if record is not None:
                        deliver(src, dst, record, now)
                        processed = True
            readers = [
                sock
                for sock, (src, dst) in peers.items()
                if not src.read_end and not dst.pending
            ]
            writers = [sock for sock, (src, _) in peers.items() if src.pending]
            if not readers and not writers:
                return
            wait = 0 if processed else min(0.5, max(0, deadline - time.monotonic()))
            readable, writable, _ = select.select(readers, writers, [], wait)
            now = time.monotonic()
            if now >= deadline:
                # Re-evaluate all state, including any deadline reset by buffered data.
                continue
            for sock in writable:
                try:
                    peers[sock][0].flush()
                except BlockingIOError:
                    continue
                last_progress = now
            for sock in readable:
                src, dst = peers[sock]
                # A complete buffered record has priority over accepting more bytes.
                if processed and src.buffer:
                    continue
                try:
                    record = src.read(now, policy)
                except BlockingIOError:
                    continue
                if record is not None:
                    deliver(src, dst, record, now)
    except BaseException:
        abort_socket(first.sock)
        abort_socket(second.sock)
        raise


def accept_session(connection, sock, address, credentials, names=None):
    if isinstance(credentials, CredentialStore):
        identity = credentials.current()
        connection.limit_to(identity.expires())
        session = server_handshake(
            sock,
            address,
            identity.key,
            identity.cert,
            identity.anchor,
            allowed_names=names,
            revocations=identity.revocations,
        )
    else:
        session = server_handshake(sock, address, *credentials, allowed_names=names)
    connection.limit_to(session.peer_expires)
    return session


def client_proxy_handler(
    remote, *, trusted_loopback=False, ingress=None, caller=None, outbound=None
):
    if trusted_loopback:
        if ingress is not None or caller is not None:
            raise ValueError("choose authenticated ingress or trusted loopback")
    elif ingress is None or not caller or not caller.strip():
        raise ValueError(
            "authenticated client-proxy requires an ingress identity and one authorized caller"
        )

    def handle(connection, local, address):
        connection.abort_on_stop = True
        local_session = None
        if trusted_loopback:
            if not (loopback(local.getsockname()[0]) and loopback(address[0])):
                raise PermissionError("trusted plaintext is restricted to loopback")
        else:
            local_session = accept_session(
                connection, local, address, ingress, (caller,)
            )
        # Admission precedes the use of upstream identity or opening an upstream socket.
        identity = outbound.current() if outbound else None
        with connection.own(
            socket.create_connection(remote, timeout=HANDSHAKE_TIMEOUT)
        ) as tunnel:
            upstream = authenticate_client(tunnel, identity=identity)
            connection.limit_to(upstream.peer_expires)
            if identity:
                connection.limit_to(identity.expires())
            relay(
                connection, Endpoint(local, local_session), Endpoint(tunnel, upstream)
            )

    return handle


def server_proxy_handler(target, credentials):
    def handle(connection, tunnel, address):
        connection.abort_on_stop = True
        session = accept_session(connection, tunnel, address, credentials)
        with connection.own(socket.create_connection(target, timeout=10)) as plain:
            relay(connection, Endpoint(plain, None), Endpoint(tunnel, session))

    return handle
