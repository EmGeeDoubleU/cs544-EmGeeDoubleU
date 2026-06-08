"""QUIC client plus a plain command-line chat UI; protocol stays hidden from input."""

import argparse
import asyncio
import ssl
import sys
from typing import Optional

from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration

from qcp.constants import ALPN_PROTOCOL, DEFAULT_PORT, FailReason
from qcp.session import Role, Session, SessionHooks
from qcp.state import State
from qcp.transport import QcpProtocol, StreamTransport

QUIT_COMMAND = "/quit"
HELP_COMMAND = "/help"
TYPING_COMMAND = "/typing"
QUIT_REASON = "user quit"

_FAIL_TEXT = {
    FailReason.BAD_USER: "unknown username",
    FailReason.BAD_PASSWORD: "wrong password",
    FailReason.LOCKED: "account locked",
}


class _UiState:
    """Holds the events the UI waits on for login and closure."""

    def __init__(self) -> None:
        """Create unset login and closed events."""
        self.logged_in: asyncio.Event = asyncio.Event()
        self.closed: asyncio.Event = asyncio.Event()


def _client_hooks(ui: _UiState) -> SessionHooks:
    """Build hooks that render session events to the terminal."""
    return SessionHooks(
        on_login_ok=lambda: _on_login_ok(ui),
        on_login_fail=lambda reason: _on_login_fail(ui, reason),
        on_chat=lambda seq, text: print(f"\npeer: {text}"),
        on_ack=lambda seq: None,
        on_typing=lambda active: print("\n[peer is typing...]" if active else "\n[peer stopped typing]"),
        on_disconnect=lambda reason: print(f"\n[peer disconnected: {reason or 'no reason'}]"),
        on_error=lambda code, desc: print(f"\n[protocol error {code}: {desc}]"),
        on_closed=ui.closed.set,
    )


def _on_login_ok(ui: _UiState) -> None:
    """Mark the session logged in and greet the user."""
    print("[connected] type a message, or /help for commands")
    ui.logged_in.set()


def _on_login_fail(ui: _UiState, reason: int) -> None:
    """Report the login failure reason to the user."""
    print(f"[login failed: {_FAIL_TEXT.get(FailReason(reason), 'unknown reason')}]")
    ui.logged_in.set()


def _build_configuration() -> QuicConfiguration:
    """Build a client QUIC/TLS configuration that trusts the self-signed cert."""
    configuration = QuicConfiguration(is_client=True, alpn_protocols=[ALPN_PROTOCOL])
    configuration.verify_mode = ssl.CERT_NONE
    return configuration


async def run_client(host: str, port: int, username: str, password: str) -> None:
    """Connect, authenticate, and run the chat UI until the session closes."""
    configuration = _build_configuration()
    async with connect(host, port, configuration=configuration, create_protocol=QcpClientProtocol) as protocol:
        await _run_session(protocol, username, password)


async def _run_session(protocol: "QcpClientProtocol", username: str, password: str) -> None:
    """Open a stream, log in, and drive the chat loop once authenticated."""
    ui = _UiState()
    session = _start_session(protocol, ui)
    session.login(username, password)
    protocol.note_activity()
    await _await_login(ui)
    if session.state is State.CONNECTED:
        await _chat_loop(session, protocol, ui)


def _start_session(protocol: "QcpClientProtocol", ui: _UiState) -> Session:
    """Allocate the bidirectional stream and bind a client session to it."""
    stream_id = protocol._quic.get_next_available_stream_id()
    transport = StreamTransport(protocol, stream_id)
    session = Session(Role.CLIENT, transport, _client_hooks(ui))
    protocol.bind_session(session, stream_id)
    return session


async def _await_login(ui: _UiState) -> None:
    """Wait until login resolves or the connection closes."""
    await _wait_any(ui.logged_in, ui.closed)


async def _chat_loop(session: Session, protocol: "QcpClientProtocol", ui: _UiState) -> None:
    """Read user input and translate each line into protocol actions."""
    while not ui.closed.is_set():
        line = await _next_line(ui)
        if line is None or not _handle_line(session, protocol, line):
            break
    await _drain_close(session, protocol, ui)


def _handle_line(session: Session, protocol: "QcpClientProtocol", line: str) -> bool:
    """Apply one input line, returning False when the user wants to quit."""
    text = line.rstrip("\n")
    if text == QUIT_COMMAND:
        return _do_quit(session, protocol)
    if text == HELP_COMMAND:
        return _show_help()
    if text == TYPING_COMMAND:
        return _do_typing(session, protocol)
    return _do_chat(session, protocol, text)


def _do_quit(session: Session, protocol: "QcpClientProtocol") -> bool:
    """Begin a graceful disconnect on user request."""
    session.disconnect(QUIT_REASON)
    protocol.note_activity()
    return False


def _show_help() -> bool:
    """Print the available chat commands."""
    print(f"commands: {HELP_COMMAND}, {TYPING_COMMAND}, {QUIT_COMMAND}; anything else is sent as chat")
    return True


def _do_typing(session: Session, protocol: "QcpClientProtocol") -> bool:
    """Send a transient typing-start then typing-stop indication."""
    session.send_typing(True)
    session.send_typing(False)
    protocol.note_activity()
    return True


def _do_chat(session: Session, protocol: "QcpClientProtocol", text: str) -> bool:
    """Send a chat line if the session is still connected."""
    if not text or session.state is not State.CONNECTED:
        return session.state is State.CONNECTED
    session.send_chat(text)
    protocol.note_activity()
    return True


async def _drain_close(session: Session, protocol: "QcpClientProtocol", ui: _UiState) -> None:
    """Wait briefly for the disconnect handshake to finish."""
    if not ui.closed.is_set():
        await _wait_any(ui.closed)


async def _next_line(ui: _UiState) -> Optional[str]:
    """Read one stdin line without blocking the event loop, or None if closed."""
    loop = asyncio.get_event_loop()
    read_task = loop.run_in_executor(None, sys.stdin.readline)
    closed_task = asyncio.ensure_future(ui.closed.wait())
    line = await _select_line(read_task, closed_task)
    return line


async def _select_line(read_task: object, closed_task: object) -> Optional[str]:
    """Return the typed line, or None if the connection closed first."""
    done, _ = await asyncio.wait({read_task, closed_task}, return_when=asyncio.FIRST_COMPLETED)
    if read_task in done:
        return read_task.result()  # type: ignore[attr-defined]
    return None


async def _wait_any(*events: asyncio.Event) -> None:
    """Wait until any of the given events is set."""
    tasks = {asyncio.ensure_future(event.wait()) for event in events}
    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    _cancel_tasks(tasks)


def _cancel_tasks(tasks: set) -> None:
    """Cancel a set of pending awaitable tasks."""
    for task in tasks:
        task.cancel()


class QcpClientProtocol(QcpProtocol):
    """Client protocol; the session is bound by the UI after connecting."""


def _parse_args() -> argparse.Namespace:
    """Parse client command-line options."""
    parser = argparse.ArgumentParser(description="QCP chat client over QUIC")
    parser.add_argument("host", help="server host or IP address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="server port")
    parser.add_argument("--username", default="bob", help="login username")
    parser.add_argument("--password", default="builder", help="login password")
    return parser.parse_args()


def main() -> None:
    """Entry point: parse arguments and run the client event loop."""
    args = _parse_args()
    try:
        asyncio.run(run_client(args.host, args.port, args.username, args.password))
    except KeyboardInterrupt:
        print("\n[client] interrupted")


if __name__ == "__main__":
    main()
