"""Stream relay. FIN is sequenced and authenticated independently in each direction."""

import socket
import threading

from .client import client_handshake
from .server import server_handshake
from .service import shutdown
from .wire import FIN, receive_record, send_record


def relay(plain, tunnel, session):
    """Forward each half until authenticated FIN; abort both sockets on malformed/truncated data."""
    errors = []

    def encrypt_stream():
        try:
            while data := plain.recv(65536):
                send_record(tunnel, session, data)
            send_record(tunnel, session, b"", FIN)
            shutdown(tunnel, socket.SHUT_WR)
        except Exception as exc:
            errors.append(exc)
            shutdown(plain)
            shutdown(tunnel)
            plain.close()
            tunnel.close()

    sender = threading.Thread(target=encrypt_stream)
    sender.start()
    try:
        while True:
            try:
                kind, data = receive_record(tunnel, session)
            except EOFError as exc:
                raise ConnectionError("tunnel ended before authenticated FIN") from exc
            if kind == FIN:
                shutdown(plain, socket.SHUT_WR)
                break
            plain.sendall(data)
    except BaseException:
        shutdown(plain)
        shutdown(tunnel)
        plain.close()
        tunnel.close()
        raise
    finally:
        sender.join()
    if errors:
        raise errors[0]


def client_proxy_handler(remote):
    def handle(service, plain, address):
        session, tunnel = client_handshake(*remote)
        with service.own(tunnel):
            relay(plain, tunnel, session)

    return handle


def server_proxy_handler(target, credentials):
    def handle(service, tunnel, address):
        session = server_handshake(tunnel, address, *credentials)
        with service.own(socket.create_connection(target, timeout=10)) as plain:
            plain.settimeout(None)
            relay(plain, tunnel, session)

    return handle
