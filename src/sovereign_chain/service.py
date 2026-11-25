"""Connection admission, ownership and trust generation changes for all listeners."""

import datetime
import logging
import math
import os
import socket
import struct
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, fields

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Timeouts:
    idle: float = 300
    write: float = 30
    drain: float = 60
    lifetime: float = 28_800

    def __post_init__(self):
        for item in fields(self):
            value = getattr(self, item.name)
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{item.name} timeout must be finite and positive")


def shutdown(sock, how=socket.SHUT_RDWR):
    try:
        sock.shutdown(how)
    except OSError:
        pass


def abort_socket(sock):
    """Abort incomplete transfers. Avoid emitting a deliberate clean write EOF."""
    linger = struct.pack("HH" if os.name == "nt" else "ii", 1, 0)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
    except OSError:
        pass
    shutdown(sock, socket.SHUT_RD)
    sock.close()


class Connection:
    """All sockets belonging to one accepted connection share one retirement state."""

    def __init__(self, sock, policy):
        self.policy = policy
        self.end = time.monotonic() + policy.lifetime
        self.lock = threading.Lock()
        self.sockets = {sock}
        self.closed = False

    def limit_to(self, expiry):
        remaining = (
            expiry - datetime.datetime.now(datetime.timezone.utc)
        ).total_seconds()
        self.end = min(self.end, time.monotonic() + remaining)

    @contextmanager
    def own(self, sock):
        with sock:
            with self.lock:
                if self.closed:
                    raise ConnectionAbortedError("connection retired")
                self.sockets.add(sock)
            try:
                yield sock
            except BaseException:
                abort_socket(sock)
                raise
            finally:
                with self.lock:
                    self.sockets.discard(sock)

    def close(self, *, abort=False):
        with self.lock:
            self.closed = True
            for sock in self.sockets:
                if abort:
                    abort_socket(sock)
                else:
                    shutdown(sock)
                    sock.close()


class TCPService:
    def __init__(self, address, handler, limit=64, *, policy=None, stores=()):
        if limit < 1:
            raise ValueError("connection limit must be positive")
        self.address = address
        self.handler = handler
        self.policy = policy or Timeouts()
        self.stores = tuple(stores)
        self.slots = threading.BoundedSemaphore(limit)
        self.stopping = threading.Event()
        self.ready = threading.Event()
        self.lock = threading.Lock()
        self.workers = {}
        self.rejected = 0

    def _retire(self, abort):
        with self.lock:
            connections = list(self.workers.values())
        for connection in connections:
            connection.close(abort=abort)

    def stop(self):
        self.stopping.set()
        self._retire(abort=False)

    def _handle(self, connection, sock, peer):
        try:
            self.handler(connection, sock, peer)
        except EOFError:
            pass
        except Exception as exc:
            connection.close(abort=True)
            if not self.stopping.is_set():
                logger.warning(
                    "Connection %s ended (%s): %s", peer, type(exc).__name__, exc
                )
        finally:
            connection.close()
            with self.lock:
                del self.workers[threading.current_thread()]
            self.slots.release()

    def _start(self, sock, peer):
        connection = Connection(sock, self.policy)
        worker = threading.Thread(target=self._handle, args=(connection, sock, peer))
        try:
            with self.lock:
                self.workers[worker] = connection
            worker.start()
        except BaseException:
            connection.close()
            self.slots.release()
            with self.lock:
                self.workers.pop(worker, None)
            raise

    def serve(self):
        for store in self.stores:
            store.refresh()
            store.current()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            if os.name == "nt":
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            listener.bind(self.address)
            listener.listen(64)
            listener.settimeout(0.2)
            self.address = listener.getsockname()
            self.ready.set()
            logger.info("Listening on %s:%s", *self.address)
            next_refresh = 0
            available = True
            try:
                while not self.stopping.is_set():
                    if self.stores and time.monotonic() >= next_refresh:
                        # Evaluate every store, even when an earlier one changed.
                        changes = [store.refresh() for store in self.stores]
                        if any(changes):
                            self._retire(abort=True)
                            logger.info(
                                "Credential generation changed; prior sessions retired"
                            )
                        available = all(store.available for store in self.stores)
                        next_refresh = time.monotonic() + 1
                    try:
                        sock, peer = listener.accept()
                    except TimeoutError:
                        continue
                    if (
                        self.stopping.is_set()
                        or not available
                        or not self.slots.acquire(blocking=False)
                    ):
                        self.rejected += 1
                        sock.close()
                        continue
                    self._start(sock, peer)
            finally:
                self.stop()
                with self.lock:
                    workers = list(self.workers)
                for worker in workers:
                    worker.join()
