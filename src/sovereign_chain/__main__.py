"""Command-line entry point for certificate setup, encrypted echo and TCP relays."""

import argparse
import getpass
import logging
import os
import sys

from .client import client_handshake
from .credentials import CLIENT_NAME, SERVER_NAME, pki_directory, server_credentials
from .pki import initialize
from .proxy import client_proxy_handler, server_proxy_handler
from .server import server_handshake
from .service import TCPService
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
        session = server_handshake(sock, peer, *credentials)
        while True:
            kind, data = receive_record(sock, session)
            if kind == FIN:
                send_record(sock, session, b"", FIN)
                return
            send_record(sock, session, b"echo: " + data)

    return handle


def echo_client(remote, message):
    session, sock = client_handshake(*remote)
    with sock:
        while True:
            if message is None:
                try:
                    line = input("msg> ")
                except EOFError:
                    return
            else:
                line = message
            send_record(sock, session, line.encode("utf-8"))
            kind, reply = receive_record(sock, session)
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
    server = commands.add_parser("server", help="run the encrypted echo server")
    client = commands.add_parser("client", help="connect to the encrypted echo server")
    left = commands.add_parser(
        "client-proxy", help="accept plain TCP and open an authenticated tunnel"
    )
    right = commands.add_parser(
        "server-proxy", help="terminate the tunnel at a fixed TCP target"
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
        if args.command == "client":
            echo_client(address(args, "remote"), args.message)
            return 0
        if args.command == "server":
            handler = echo_handler(server_credentials())
        elif args.command == "client-proxy":
            handler = client_proxy_handler(address(args, "remote"))
        else:
            handler = server_proxy_handler(
                address(args, "target"), server_credentials()
            )
        TCPService(address(args, "listen"), handler, args.max_connections).serve()
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
