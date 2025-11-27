"""User-space XOR proxy for macOS.

This utility emulates the behavior of the Linux `ipt_xor` target by XOR-obfuscating
traffic that is diverted to it. It is intended to be used alongside macOS PF rules
that redirect packets to a local port handled by this proxy.
"""
from __future__ import annotations

import argparse
import logging
import selectors
import signal
import socket
import sys
import threading
from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass
class ProxyConfig:
    listen_host: str
    listen_port: int
    upstream_host: str
    upstream_port: int
    protocol: str
    key: bytes
    udp_idle_timeout: float = 30.0


class GracefulExit(SystemExit):
    """Raised when a termination signal is received."""


def parse_key(raw_key: str) -> bytes:
    """Parse a key provided as text or hex (prefixed with ``0x``).

    The key is used cyclically for XOR operations.
    """

    if raw_key.startswith("0x"):
        hex_string = raw_key[2:]
        if len(hex_string) % 2:
            hex_string = "0" + hex_string
        try:
            return bytes.fromhex(hex_string)
        except ValueError as exc:  # pragma: no cover - defensive
            raise argparse.ArgumentTypeError(f"Invalid hex key: {raw_key}") from exc
    return raw_key.encode()


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """Apply XOR between ``data`` and ``key`` in a cyclic manner."""

    if not key:
        return data
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="[%(asctime)s] %(levelname)s: %(message)s",
    )


class TCPProxy:
    def __init__(self, config: ProxyConfig) -> None:
        self.config = config
        self._stop_event = threading.Event()

    def start(self) -> None:
        logging.info(
            "Starting TCP XOR proxy on %s:%s -> %s:%s",
            self.config.listen_host,
            self.config.listen_port,
            self.config.upstream_host,
            self.config.upstream_port,
        )
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((self.config.listen_host, self.config.listen_port))
            server_sock.listen()
            server_sock.settimeout(1.0)

            while not self._stop_event.is_set():
                try:
                    client_sock, addr = server_sock.accept()
                except socket.timeout:
                    continue
                logging.info("Accepted connection from %s:%s", *addr)
                handler = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock,),
                    daemon=True,
                )
                handler.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _handle_client(self, client_sock: socket.socket) -> None:
        with client_sock, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as upstream:
            upstream.connect((self.config.upstream_host, self.config.upstream_port))
            logging.debug("Connected upstream %s:%s", self.config.upstream_host, self.config.upstream_port)

            threads = [
                threading.Thread(
                    target=self._pipe,
                    args=(client_sock, upstream, "client->upstream"),
                    daemon=True,
                ),
                threading.Thread(
                    target=self._pipe,
                    args=(upstream, client_sock, "upstream->client"),
                    daemon=True,
                ),
            ]
            for thread in threads:
                thread.start()

            for thread in threads:
                thread.join()

    def _pipe(self, source: socket.socket, destination: socket.socket, label: str) -> None:
        while True:
            try:
                chunk = source.recv(4096)
                if not chunk:
                    logging.debug("%s closed", label)
                    break
                transformed = xor_bytes(chunk, self.config.key)
                destination.sendall(transformed)
            except OSError as exc:  # pragma: no cover - defensive
                logging.debug("Socket error in %s: %s", label, exc)
                break


class UDPProxy:
    def __init__(self, config: ProxyConfig) -> None:
        self.config = config
        self._stop_event = threading.Event()

    def start(self) -> None:
        logging.info(
            "Starting UDP XOR proxy on %s:%s -> %s:%s",
            self.config.listen_host,
            self.config.listen_port,
            self.config.upstream_host,
            self.config.upstream_port,
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listen_sock, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_sock:
            listen_sock.bind((self.config.listen_host, self.config.listen_port))
            listen_sock.setblocking(False)
            upstream_sock.setblocking(False)

            sel = selectors.DefaultSelector()
            sel.register(listen_sock, selectors.EVENT_READ, data="client")
            sel.register(upstream_sock, selectors.EVENT_READ, data="upstream")

            last_client: Optional[tuple[str, int]] = None

            while not self._stop_event.is_set():
                events = sel.select(timeout=1.0)
                for key, _ in events:
                    if key.data == "client":
                        try:
                            data, addr = listen_sock.recvfrom(65535)
                        except OSError:
                            continue
                        last_client = addr
                        upstream_sock.sendto(xor_bytes(data, self.config.key), (self.config.upstream_host, self.config.upstream_port))
                    else:
                        try:
                            data, _ = upstream_sock.recvfrom(65535)
                        except OSError:
                            continue
                        if last_client:
                            listen_sock.sendto(xor_bytes(data, self.config.key), last_client)

    def stop(self) -> None:
        self._stop_event.set()


def parse_args(argv: Iterable[str]) -> ProxyConfig:
    parser = argparse.ArgumentParser(description="User-space XOR proxy for macOS PF redirection")
    parser.add_argument("--listen-host", default="0.0.0.0", help="Host/IP to listen on (default: 0.0.0.0)")
    parser.add_argument("--listen-port", type=int, required=True, help="Local port to listen on")
    parser.add_argument("--upstream-host", required=True, help="Destination host to forward traffic to")
    parser.add_argument("--upstream-port", type=int, required=True, help="Destination port to forward traffic to")
    parser.add_argument("--protocol", choices=["tcp", "udp"], default="tcp", help="Protocol to proxy (default: tcp)")
    parser.add_argument("--key", type=parse_key, required=True, help="XOR key (text or hex starting with 0x)")
    parser.add_argument("--udp-idle-timeout", type=float, default=30.0, help="Idle timeout for UDP clients (currently informational)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args(list(argv))
    return ProxyConfig(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        upstream_host=args.upstream_host,
        upstream_port=args.upstream_port,
        protocol=args.protocol,
        key=args.key,
        udp_idle_timeout=args.udp_idle_timeout,
    )


def install_signal_handlers(proxy: TCPProxy | UDPProxy) -> None:
    def _handler(signum, _frame):  # pragma: no cover - runtime behavior
        logging.info("Received signal %s, shutting down", signum)
        proxy.stop()
        raise GracefulExit()

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, _handler)


def main(argv: Optional[Iterable[str]] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    try:
        config = parse_args(argv)
    except argparse.ArgumentError:
        return 2

    configure_logging(verbose="--verbose" in sys.argv)
    proxy: TCPProxy | UDPProxy
    if config.protocol == "tcp":
        proxy = TCPProxy(config)
    else:
        proxy = UDPProxy(config)

    install_signal_handlers(proxy)

    try:
        proxy.start()
    except GracefulExit:
        pass
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
