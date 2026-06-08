"""QUIC server: binds a port, accepts connections, runs a session per connection."""

import argparse
import asyncio
from functools import partial

from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration

from qcp.constants import ALPN_PROTOCOL, DEFAULT_PORT
from qcp.session import Authenticator, Role, Session, SessionHooks
from qcp.transport import QcpProtocol, StreamTransport

DEFAULT_HOST = "localhost"
DEFAULT_CERT = "certs/cert.pem"
DEFAULT_KEY = "certs/key.pem"


class QcpServerProtocol(QcpProtocol):
    """Server protocol that lazily creates an authenticated session per connection."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        """Capture the shared authenticator before initializing the base protocol."""
        self._authenticator: Authenticator = kwargs.pop("authenticator")  # type: ignore[assignment]
        super().__init__(*args, **kwargs)

    def _ensure_session(self, stream_id: int) -> None:
        """Create the server session bound to the first stream seen."""
        if self._session is not None:
            return
        transport = StreamTransport(self, stream_id)
        session = Session(Role.SERVER, transport, _server_hooks(), self._authenticator)
        self.bind_session(session, stream_id)


def _server_hooks() -> SessionHooks:
    """Build hooks that log server-side session events to the console."""
    return SessionHooks(
        on_login_ok=lambda: print("[server] client authenticated"),
        on_login_fail=lambda reason: print(f"[server] login failed reason={reason}"),
        on_chat=lambda seq, text: print(f"[server] chat #{seq}: {text}"),
        on_typing=lambda active: print(f"[server] peer typing={active}"),
        on_disconnect=lambda reason: print(f"[server] disconnect: {reason!r}"),
        on_error=lambda code, desc: print(f"[server] error code={code}: {desc}"),
        on_closed=lambda: print("[server] session closed"),
    )


def _build_configuration(cert: str, key: str) -> QuicConfiguration:
    """Build the server QUIC/TLS configuration from a cert and key path."""
    configuration = QuicConfiguration(is_client=False, alpn_protocols=[ALPN_PROTOCOL])
    configuration.load_cert_chain(cert, key)
    return configuration


async def run_server(host: str, port: int, cert: str, key: str) -> None:
    """Serve QCP connections until the process is interrupted."""
    configuration = _build_configuration(cert, key)
    authenticator = Authenticator()
    create = partial(QcpServerProtocol, authenticator=authenticator)
    await serve(host, port, configuration=configuration, create_protocol=create)
    print(f"[server] listening on {host}:{port}")
    await asyncio.Future()


def _parse_args() -> argparse.Namespace:
    """Parse server command-line options."""
    parser = argparse.ArgumentParser(description="QCP chat server over QUIC")
    parser.add_argument("--host", default=DEFAULT_HOST, help="bind address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="bind port")
    parser.add_argument("--cert", default=DEFAULT_CERT, help="TLS certificate path")
    parser.add_argument("--key", default=DEFAULT_KEY, help="TLS private key path")
    return parser.parse_args()


def main() -> None:
    """Entry point: parse arguments and run the server event loop."""
    args = _parse_args()
    try:
        asyncio.run(run_server(args.host, args.port, args.cert, args.key))
    except KeyboardInterrupt:
        print("\n[server] shutting down")


if __name__ == "__main__":
    main()
