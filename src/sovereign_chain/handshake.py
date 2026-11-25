"""SC-EE-3 key schedule and bounded replay window shared by both endpoints."""

import threading
import time
from collections import OrderedDict

from cryptography.hazmat.primitives.asymmetric import ed25519

from .security import PROTO_VER, Session, hkdf
from .wire import ProtocolError

KEY_FIELDS = (b"KEYEXCHANGE1|", b"KEYEXCHANGE2|", b"KEYCONFIRM1|", b"KEYCONFIRM2|")


class ReplayWindow:
    """Keep recent nonces under a lock. Eviction bounds storage per process."""

    def __init__(self, capacity=10_000, ttl=300):
        self.entries = OrderedDict()
        self.lock = threading.Lock()
        self.capacity = capacity
        self.ttl = ttl

    def remember(self, nonce):
        with self.lock:
            now = time.monotonic()
            while self.entries and next(iter(self.entries.values())) <= now - self.ttl:
                self.entries.popitem(last=False)
            if nonce in self.entries:
                raise ProtocolError("repeated handshake nonce")
            if len(self.entries) >= self.capacity:
                self.entries.popitem(last=False)
            self.entries[nonce] = now


def key_context(suite, client_nonce, server_nonce):
    return b"|".join((b"SC-HKDF", PROTO_VER, suite, client_nonce, server_nonce))


def make_session(role, suite, shared, context, fields, seed, transcript):
    # The on-wire SC-EE-3 key schedule orders C->S before S->C on both peers.
    keys = hkdf(shared, b"|".join((context, *fields)), length=64)
    client_key, server_key = keys[:32], keys[32:]
    send, receive = (
        (client_key, server_key) if role == "client" else (server_key, client_key)
    )
    return Session(
        send, receive, seed, role=role, session_id=transcript, cipher_suite=suite
    )


def verify_peer_signature(cert, signature, transcript):
    public = cert.public_key()
    if not isinstance(public, ed25519.Ed25519PublicKey):
        raise ProtocolError("peer authentication requires Ed25519")
    public.verify(signature, transcript)
