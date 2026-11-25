"""Length-prefixed records shared by the handshake, echo example and TCP relays."""

import hashlib
import struct
import time

from .security import MAX_FRAME_SIZE

LENGTH = struct.Struct(">I")
SEQUENCE = struct.Struct(">Q")
HANDSHAKE_TIMEOUT = 15
DATA = b"DATA"
FIN = b"FIN!"


class ProtocolError(ValueError):
    """The peer sent a record that does not belong to the current protocol state."""


def pack(payload):
    if len(payload) > MAX_FRAME_SIZE:
        raise ProtocolError("frame exceeds size limit")
    return LENGTH.pack(len(payload)) + payload


def recv_exact(sock, count, deadline=None):
    result = bytearray()
    while len(result) < count:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("handshake deadline exceeded")
            sock.settimeout(remaining)
        part = sock.recv(min(count - len(result), 65536))
        if not part:
            if not result:
                raise EOFError("peer closed the stream")
            raise ProtocolError("truncated frame")
        result.extend(part)
    return bytes(result)


def recv_frame(sock, deadline=None):
    (length,) = LENGTH.unpack(recv_exact(sock, LENGTH.size, deadline))
    if not 0 < length <= MAX_FRAME_SIZE:
        raise ProtocolError("invalid frame length")
    try:
        return recv_exact(sock, length, deadline)
    except EOFError as exc:
        raise ProtocolError("truncated frame body") from exc


class HandshakeIO:
    """Hash frame bodies in wire order and share one deadline across all seven steps."""

    def __init__(self, sock):
        self.sock = sock
        self.digest = hashlib.sha256()
        self.deadline = time.monotonic() + HANDSHAKE_TIMEOUT

    def receive(self):
        frame = recv_frame(self.sock, self.deadline)
        self.digest.update(frame)
        return frame

    def send(self, *frames):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("handshake deadline exceeded")
        self.sock.settimeout(remaining)
        self.sock.sendall(b"".join(pack(frame) for frame in frames))
        for frame in frames:
            self.digest.update(frame)


def payload(frame, prefix, size=None):
    if not frame.startswith(prefix):
        raise ProtocolError("unexpected handshake frame")
    body = frame[len(prefix) :]
    if size is not None and len(body) != size:
        raise ProtocolError("unexpected handshake field length")
    return body


def send_record(sock, session, data, kind=DATA):
    sequence, ciphertext = session.encrypt_with_sequence(data, frame_type=kind)
    sock.sendall(pack(kind + SEQUENCE.pack(sequence) + ciphertext))


def receive_record(sock, session):
    frame = recv_frame(sock)
    kind = frame[:4]
    if kind not in (DATA, FIN) or len(frame) < 12:
        raise ProtocolError("invalid application record")
    (sequence,) = SEQUENCE.unpack_from(frame, 4)
    data = session.decrypt_with_sequence(sequence, frame[12:], frame_type=kind)
    if kind == FIN and data:
        raise ProtocolError("FIN record must have an empty body")
    return kind, data
