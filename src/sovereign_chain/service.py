"""A bounded TCP listener shared by the echo server and both proxies."""

import logging
import socket
import threading
from contextlib import contextmanager

logger = logging.getLogger(__name__)


def shutdown(sock, how=socket.SHUT_RDWR):
    try:
        sock.shutdown(how)
    except OSError:
        pass  # The other worker or the peer may already have closed this direction.


class TCPService:
    """Single-use listener. Each accepted connection occupies one slot until its handler exits."""

    def __init__(self, address, handler, limit=64):
        if limit < 1:
            raise ValueError("connection limit must be positive")
        self.address = address
        self.handler = handler
        self.slots = threading.BoundedSemaphore(limit)
        self.stopping = threading.Event()
        self.ready = threading.Event()
        self.lock = threading.Lock()
        self.sockets = set()
        self.workers = set()

    @contextmanager
    def own(self, sock):
        """Track both ends so stop() can interrupt either direction of a blocked relay."""
        with sock:
            with self.lock:
                if self.stopping.is_set():
                    raise ConnectionAbortedError("service stopped")
                self.sockets.add(sock)
            try:
                yield sock
            finally:
                with self.lock:
                    self.sockets.discard(sock)

    def stop(self):
        self.stopping.set()
        with self.lock:
            for sock in self.sockets:
                shutdown(sock)
                sock.close()  # Wake pending Winsock reads as well as POSIX reads.

    def _handle(self, conn, address):
        try:
            with self.own(conn):
                self.handler(self, conn, address)
        except EOFError:
            pass  # An echo client may close at a record boundary.
        except Exception as exc:
            if not self.stopping.is_set():
                logger.warning(
                    "Connection %s ended (%s): %s", address, type(exc).__name__, exc
                )
        finally:
            self.slots.release()
            with self.lock:
                self.workers.discard(threading.current_thread())

    def serve(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(self.address)
            listener.listen(64)
            listener.settimeout(
                0.2
            )  # Wake the accept loop even when there are no clients.
            self.address = listener.getsockname()
            self.ready.set()
            logger.info("Listening on %s:%s", *self.address)
            try:
                while not self.stopping.is_set():
                    try:
                        conn, address = listener.accept()
                    except TimeoutError:
                        continue
                    # Reject excess work before allocating a thread or queuing a handshake.
                    if not self.slots.acquire(blocking=False):
                        conn.close()
                        continue
                    worker = threading.Thread(target=self._handle, args=(conn, address))
                    try:
                        with self.lock:
                            self.workers.add(worker)
                        worker.start()
                    except BaseException:
                        conn.close()
                        self.slots.release()
                        with self.lock:
                            self.workers.discard(worker)
                        raise
            finally:
                self.stop()
                with self.lock:
                    workers = list(self.workers)
                for worker in workers:
                    worker.join()
