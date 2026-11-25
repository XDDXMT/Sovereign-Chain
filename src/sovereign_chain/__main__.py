"""Command-line entry point for certificate setup, encrypted echo and TCP relays."""

import argparse
import getpass
import logging
import os
import socket
import sys
import time

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend

from .client import client_handshake
from .credentials import (
    CLIENT_NAME,
    SERVER_NAME,
    CredentialStore,
    load_certificate,
    pki_directory,
)
from .pki import initialize
from .proxy import accept_session, client_proxy_handler, loopback, server_proxy_handler
from .service import TCPService, Timeouts
from .trust import public_key_id, validate_ca_certificate
from .wire import DATA, FIN, ProtocolError, receive_record, send_record


def address_options(parser, prefix, host_env, port_env, port):
    parser.add_argument(
        f"--{prefix}-host", default=os.getenv(host_env, "127.0.0.1"), help=host_env
    )
    parser.add_argument(
        f"--{prefix}-port",
        type=int,
        default=os.getenv(port_env, str(port)),
        help=port_env,
    )


def address(args, prefix):
    host = getattr(args, prefix + "_host")
    port = getattr(args, prefix + "_port")
    minimum = 0 if prefix == "listen" else 1
    if not host or not minimum <= port <= 65535:
        raise ValueError(f"invalid {prefix} address")
    return host, port


def echo_handler(credentials):
    def handle(service, sock, peer):
        session = accept_session(service, sock, peer, credentials)
        while True:
            kind, data = receive_record(
                sock, session, min(service.end, time.monotonic() + service.policy.idle)
            )
            remaining = min(service.policy.write, service.end - time.monotonic())
            if remaining <= 0:
                raise TimeoutError("session expired")
            sock.settimeout(remaining)
            if kind == FIN:
                send_record(sock, session, b"", FIN)
                return
            send_record(sock, session, b"echo: " + data)

    return handle


def echo_client(remote, message, policy):
    session, sock = client_handshake(*remote)
    with sock:
        end = min(
            time.monotonic() + policy.lifetime,
            time.monotonic() + session.peer_expires.timestamp() - time.time(),
        )
        while True:
            if message is None:
                try:
                    line = input("msg> ")
                except EOFError:
                    sock.settimeout(policy.write)
                    send_record(sock, session, b"", FIN)
                    sock.shutdown(socket.SHUT_WR)
                    return
            else:
                line = message
            remaining = min(policy.write, end - time.monotonic())
            if remaining <= 0:
                raise TimeoutError("session expired")
            sock.settimeout(remaining)
            send_record(sock, session, line.encode("utf-8"))
            if message is not None:
                send_record(sock, session, b"", FIN)
                sock.shutdown(socket.SHUT_WR)
            kind, reply = receive_record(
                sock, session, min(end, time.monotonic() + policy.idle)
            )
            if kind != DATA:
                raise ProtocolError("expected an echo reply")
            print(reply.decode("utf-8", errors="replace"))
            if message is not None:
                return


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="sovereign-chain", description="SC-EE-3 authenticated TCP service"
    )
    commands = parser.add_subparsers(required=True, dest="command")
    pki = commands.add_parser(
        "init-pki", help="issue a fresh CA and two named endpoints"
    )
    pki.add_argument("--out", default=str(pki_directory()))
    pki.add_argument("--server-name", default=os.getenv("SC_SERVER_NAME", SERVER_NAME))
    pki.add_argument("--client-name", default=CLIENT_NAME)
    inspect = commands.add_parser(
        "trust-info",
        help="identify the configured public trust anchor and native crypto backend",
    )
    inspect.add_argument("--role", choices=("client", "server"), default="server")
    server = commands.add_parser("server", help="run the encrypted echo server")
    client = commands.add_parser("client", help="connect to the encrypted echo server")
    left = commands.add_parser(
        "client-proxy", help="authenticate one caller and relay to a fixed SC endpoint"
    )
    right = commands.add_parser(
        "server-proxy", help="terminate the tunnel at a fixed TCP target"
    )
    left.add_argument(
        "--ingress-pki-dir",
        default=os.getenv("SC_INGRESS_PKI_DIR"),
        help="dedicated incoming server credentials",
    )
    left.add_argument(
        "--ingress-client-name",
        default=os.getenv("SC_INGRESS_CLIENT_NAME"),
        help="one authorized incoming SAN",
    )
    left.add_argument(
        "--trusted-loopback",
        action="store_true",
        help="opt in to plaintext TCP on a single-user loopback interface",
    )
    address_options(server, "listen", "SC_LISTEN_HOST", "SC_LISTEN_PORT", 5555)
    address_options(client, "remote", "SC_SERVER_HOST", "SC_SERVER_PORT", 5555)
    client.add_argument("--message", help="send one UTF-8 message and exit")
    address_options(
        left,
        "listen",
        "SC_CLIENT_PROXY_LISTEN_HOST",
        "SC_CLIENT_PROXY_LISTEN_PORT",
        3398,
    )
    address_options(left, "remote", "SC_SERVER_HOST", "SC_SERVER_PORT", 25558)
    address_options(
        right, "listen", "SC_PROXY_LISTEN_HOST", "SC_PROXY_LISTEN_PORT", 25558
    )
    address_options(
        right, "target", "SC_PROXY_TARGET_HOST", "SC_PROXY_TARGET_PORT", 8000
    )
    for command in (server, left, right):
        command.add_argument(
            "--max-connections", type=int, default=os.getenv("SC_MAX_CONNECTIONS", "64")
        )
    for command in (server, client, left, right):
        for option, attr in (
            ("idle-timeout", "idle"),
            ("write-timeout", "write"),
            ("drain-timeout", "drain"),
            ("max-session-age", "lifetime"),
        ):
            if attr == "drain" and command is client:
                command.set_defaults(drain=Timeouts().drain)
                continue
            command.add_argument(
                "--" + option,
                dest=attr,
                type=float,
                default=os.getenv(
                    "SC_" + option.upper().replace("-", "_"),
                    str(getattr(Timeouts(), attr)),
                ),
            )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        if args.command == "init-pki":
            password = os.getenv("SC_CA_KEY_PASSWORD") or getpass.getpass(
                "New CA private-key password: "
            )
            print(
                initialize(
                    args.out, password.encode(), args.server_name, args.client_name
                )
            )
            return 0
        if args.command == "trust-info":
            anchor = load_certificate(args.role, ca=True)
            print("CA SPKI SHA-256", public_key_id(anchor.public_key()))
            print("CA not after", anchor.not_valid_after_utc.isoformat())
            print(
                "cryptography",
                cryptography.__version__,
                "/",
                backend.openssl_version_text(),
            )
            validate_ca_certificate(anchor)
            return 0
        policy = Timeouts(args.idle, args.write, args.drain, args.lifetime)
        if args.command == "client":
            echo_client(address(args, "remote"), args.message, policy)
            return 0
        listen = address(args, "listen")
        if args.command == "client-proxy":
            if args.trusted_loopback and not loopback(listen[0]):
                raise ValueError(
                    "--trusted-loopback requires a literal loopback listen address"
                )
            outbound = CredentialStore("client")
            ingress = (
                CredentialStore("server", ingress_dir=args.ingress_pki_dir)
                if args.ingress_pki_dir
                else None
            )
            handler = client_proxy_handler(
                address(args, "remote"),
                trusted_loopback=args.trusted_loopback,
                ingress=ingress,
                caller=args.ingress_client_name,
                outbound=outbound,
            )
            stores = [outbound] if ingress is None else [ingress, outbound]
        else:
            authority = CredentialStore("server")
            stores = [authority]
            handler = (
                echo_handler(authority)
                if args.command == "server"
                else server_proxy_handler(address(args, "target"), authority)
            )
        TCPService(
            listen, handler, args.max_connections, policy=policy, stores=stores
        ).serve()
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
