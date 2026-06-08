"""End-to-end test driving a real client and server over QUIC."""

import asyncio
import ssl
from functools import partial
from pathlib import Path

import pytest

from aioquic.asyncio import serve
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration

from qcp.client import QcpClientProtocol
from qcp.constants import ALPN_PROTOCOL
from qcp.server import QcpServerProtocol
from qcp.session import Authenticator, Role, Session, SessionHooks
from qcp.state import State
from qcp.transport import StreamTransport

CERT = Path("certs/cert.pem")
KEY = Path("certs/key.pem")
E2E_PORT = 44330
WAIT_SEC = 5.0

pytestmark = pytest.mark.skipif(
    not (CERT.exists() and KEY.exists()), reason="run 'make certs' first"
)


def test_end_to_end_chat_round_trip() -> None:
    """A real client logs in, exchanges a chat/ack, and disconnects cleanly."""
    result = asyncio.run(_round_trip())
    assert result is State.CLOSED


async def _round_trip() -> State:
    """Start a server, run one client scenario, and return its final state."""
    server = await _start_server()
    try:
        return await _client_scenario()
    finally:
        server.close()


async def _start_server() -> object:
    """Bind a QCP server on the end-to-end test port."""
    configuration = QuicConfiguration(is_client=False, alpn_protocols=[ALPN_PROTOCOL])
    configuration.load_cert_chain(str(CERT), str(KEY))
    create = partial(QcpServerProtocol, authenticator=Authenticator())
    return await serve("localhost", E2E_PORT, configuration=configuration, create_protocol=create)


async def _client_scenario() -> State:
    """Connect a client and walk it through the full happy-path exchange."""
    configuration = QuicConfiguration(is_client=True, alpn_protocols=[ALPN_PROTOCOL])
    configuration.verify_mode = ssl.CERT_NONE
    async with connect(
        "localhost", E2E_PORT, configuration=configuration, create_protocol=QcpClientProtocol
    ) as protocol:
        return await _drive(protocol)


async def _drive(protocol: QcpClientProtocol) -> State:
    """Log in, send a chat, await its ack, then disconnect."""
    events = _Events()
    session = _bind(protocol, events)
    await _login(session, protocol, events)
    await _chat(session, protocol, events)
    await _quit(session, protocol, events)
    return session.state


class _Events:
    """Awaitable flags for the milestones of the client scenario."""

    def __init__(self) -> None:
        """Create unset login, ack, and closed events."""
        self.logged_in: asyncio.Event = asyncio.Event()
        self.acked: asyncio.Event = asyncio.Event()
        self.closed: asyncio.Event = asyncio.Event()


def _bind(protocol: QcpClientProtocol, events: _Events) -> Session:
    """Attach a capturing client session to a fresh bidirectional stream."""
    hooks = SessionHooks(
        on_login_ok=events.logged_in.set,
        on_ack=lambda seq: events.acked.set(),
        on_closed=events.closed.set,
    )
    stream_id = protocol._quic.get_next_available_stream_id()
    session = Session(Role.CLIENT, StreamTransport(protocol, stream_id), hooks)
    protocol.bind_session(session, stream_id)
    return session


async def _login(session: Session, protocol: QcpClientProtocol, events: _Events) -> None:
    """Send credentials and wait for the server to accept them."""
    session.login("bob", "builder")
    protocol.note_activity()
    await asyncio.wait_for(events.logged_in.wait(), WAIT_SEC)


async def _chat(session: Session, protocol: QcpClientProtocol, events: _Events) -> None:
    """Send one chat line and wait for its acknowledgement."""
    session.send_chat("ping")
    protocol.note_activity()
    await asyncio.wait_for(events.acked.wait(), WAIT_SEC)


async def _quit(session: Session, protocol: QcpClientProtocol, events: _Events) -> None:
    """Initiate a graceful disconnect and wait for closure."""
    session.disconnect("done")
    protocol.note_activity()
    await asyncio.wait_for(events.closed.wait(), WAIT_SEC)
