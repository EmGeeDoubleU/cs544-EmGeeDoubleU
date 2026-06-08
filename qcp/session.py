"""Per-connection QCP protocol engine shared by client and server endpoints."""

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, ClassVar, Optional, Protocol

from qcp import pdu
from qcp.constants import (
    LOCK_WINDOW_SEC,
    MAX_LOGIN_FAILS,
    SEQ_NUM_START,
    FailReason,
)
from qcp.errors import ProtocolViolationError, QCPError
from qcp.pdu import (
    Ack,
    ChatMsg,
    Disconnect,
    Error,
    LoginFail,
    LoginOk,
    LoginReq,
    TypingStart,
    TypingStop,
)
from qcp.state import Event, State, transition


class Role(Enum):
    """Identifies which endpoint a session represents."""

    CLIENT = auto()
    SERVER = auto()


class Transport(Protocol):
    """Minimal byte sink the session writes frames to and can close."""

    def send_bytes(self, data: bytes) -> None:
        """Write raw frame bytes to the peer."""

    def close(self) -> None:
        """Tear down the underlying connection."""


@dataclass
class SessionHooks:
    """Injected callbacks letting a UI observe session events."""

    on_login_ok: Callable[[], None] = lambda: None
    on_login_fail: Callable[[int], None] = lambda reason: None
    on_chat: Callable[[int, str], None] = lambda seq, text: None
    on_ack: Callable[[int], None] = lambda seq: None
    on_typing: Callable[[bool], None] = lambda active: None
    on_disconnect: Callable[[str], None] = lambda reason: None
    on_error: Callable[[int, str], None] = lambda code, desc: None
    on_closed: Callable[[], None] = lambda: None


CREDENTIALS: dict[str, str] = {"bob": "builder", "admin": "admin123"}


class Authenticator:
    """Validates demo credentials with an in-memory lockout counter."""

    def __init__(
        self,
        credentials: Optional[dict[str, str]] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Store the credential table and a clock for the lockout window."""
        self._credentials: dict[str, str] = credentials or dict(CREDENTIALS)
        self._clock: Callable[[], float] = clock
        self._failures: dict[str, list[float]] = {}

    def authenticate(self, username: str, password: str) -> Optional[FailReason]:
        """Return a fail reason for bad credentials, or None on success."""
        if username not in self._credentials:
            return FailReason.BAD_USER
        if self._is_locked(username):
            return FailReason.LOCKED
        if self._credentials[username] != password:
            return self._record_failure(username)
        self._failures.pop(username, None)
        return None

    def _is_locked(self, username: str) -> bool:
        """Report whether recent failures have locked the account."""
        return len(self._recent_failures(username)) >= MAX_LOGIN_FAILS

    def _record_failure(self, username: str) -> FailReason:
        """Record a failed attempt and report LOCKED once the threshold trips."""
        recent = self._recent_failures(username)
        recent.append(self._clock())
        self._failures[username] = recent
        if len(recent) >= MAX_LOGIN_FAILS:
            return FailReason.LOCKED
        return FailReason.BAD_PASSWORD

    def _recent_failures(self, username: str) -> list[float]:
        """Return failure timestamps still inside the lockout window."""
        cutoff = self._clock() - LOCK_WINDOW_SEC
        return [stamp for stamp in self._failures.get(username, []) if stamp >= cutoff]


@dataclass
class Session:
    """Drives the QCP DFA and message exchange for one connection."""

    role: Role
    transport: Transport
    hooks: SessionHooks = field(default_factory=SessionHooks)
    authenticator: Optional[Authenticator] = None
    state: State = State.INIT
    username: Optional[str] = None
    _send_seq: int = 0
    _unacked: set[int] = field(default_factory=set)
    _acked: set[int] = field(default_factory=set)
    _torn_down: bool = False

    def login(self, username: str, password: str) -> None:
        """Client action: send credentials and enter AUTHENTICATING."""
        self._send(pdu.build_login_req(username, password))
        self.username = username
        self._advance(Event.SEND_LOGIN_REQ)

    def send_chat(self, text: str) -> int:
        """Client/peer action: send a chat line and track its sequence number."""
        self._send_seq += 1
        seq = self._send_seq
        self._advance(Event.SEND_CHAT)
        self._unacked.add(seq)
        self._send(pdu.build_chat_msg(seq, text))
        return seq

    def send_typing(self, active: bool) -> None:
        """Client/peer action: signal typing start or stop without state change."""
        frame = pdu.build_typing_start() if active else pdu.build_typing_stop()
        self._send(frame)
        self._advance(Event.SEND_TYPING)

    def disconnect(self, reason: str = "") -> None:
        """Client/peer action: begin a graceful disconnect handshake."""
        self._send(pdu.build_disconnect(reason))
        self._advance(Event.SEND_DISCONNECT)

    def receive(self, frame: bytes) -> None:
        """Validate and process one complete inbound frame."""
        if self.state is State.CLOSED:
            return
        try:
            self._dispatch(pdu.parse_frame(frame))
        except QCPError as exc:
            self._fail(exc)

    def on_auth_timeout(self) -> None:
        """Bounded-wait expiry while authenticating closes the session."""
        self._timeout(Event.AUTH_TIMEOUT)

    def on_disconnect_timeout(self) -> None:
        """Bounded-wait expiry while disconnecting closes the session."""
        self._timeout(Event.DISCONNECT_TIMEOUT)

    def on_idle_timeout(self) -> None:
        """Idle expiry while connected starts a disconnect with a reason."""
        if self.state is not State.CONNECTED:
            return
        self._send(pdu.build_disconnect("idle timeout"))
        self._advance(Event.IDLE_TIMEOUT)

    def abort(self) -> None:
        """Force closure without further protocol I/O, e.g. on transport loss."""
        self._close()

    def _dispatch(self, message: object) -> None:
        """Route a parsed PDU to its handler, treating ERROR specially."""
        if isinstance(message, Error):
            self._on_error(message)
            return
        self._HANDLERS[type(message)](self, message)

    def _on_login_req(self, message: LoginReq) -> None:
        """Server handler: authenticate credentials and answer accordingly."""
        self._advance(Event.RECV_LOGIN_REQ)
        reason = self._run_auth(message)
        if reason is None:
            self._accept_login(message.username)
            return
        self._reject_login(reason)

    def _run_auth(self, message: LoginReq) -> Optional[FailReason]:
        """Apply the injected authenticator to a login request."""
        if self.authenticator is None:
            return FailReason.BAD_USER
        return self.authenticator.authenticate(message.username, message.password)

    def _accept_login(self, username: str) -> None:
        """Server step: confirm login and enter CONNECTED."""
        self.username = username
        self._send(pdu.build_login_ok())
        self._advance(Event.SEND_LOGIN_OK)
        self.hooks.on_login_ok()

    def _reject_login(self, reason: FailReason) -> None:
        """Server step: report failure then close the connection."""
        self._send(pdu.build_login_fail(reason))
        self._advance(Event.SEND_LOGIN_FAIL)
        self.hooks.on_login_fail(reason)
        self._close()

    def _on_login_ok(self, message: LoginOk) -> None:
        """Client handler: enter CONNECTED on acceptance."""
        self._advance(Event.RECV_LOGIN_OK)
        self.hooks.on_login_ok()

    def _on_login_fail(self, message: LoginFail) -> None:
        """Client handler: surface the reason and close on rejection."""
        self._advance(Event.RECV_LOGIN_FAIL)
        self.hooks.on_login_fail(message.reason)
        self._close()

    def _on_chat(self, message: ChatMsg) -> None:
        """Either handler: deliver a chat line and acknowledge it."""
        self._advance(Event.RECV_CHAT)
        self.hooks.on_chat(message.seq_num, message.text)
        self._send(pdu.build_ack(message.seq_num))
        self._advance(Event.SEND_ACK)

    def _on_ack(self, message: Ack) -> None:
        """Either handler: validate and clear a pending acknowledgement."""
        self._advance(Event.RECV_ACK)
        self._validate_ack(message.seq_num)
        self._unacked.discard(message.seq_num)
        self._acked.add(message.seq_num)
        self.hooks.on_ack(message.seq_num)

    def _validate_ack(self, seq: int) -> None:
        """Reject an ACK for a sequence never sent or already acknowledged."""
        if seq not in self._unacked:
            raise ProtocolViolationError(f"stale or duplicate ack {seq}")

    def _on_typing_start(self, message: TypingStart) -> None:
        """Either handler: surface a typing-start indication."""
        self._advance(Event.RECV_TYPING)
        self.hooks.on_typing(True)

    def _on_typing_stop(self, message: TypingStop) -> None:
        """Either handler: surface a typing-stop indication."""
        self._advance(Event.RECV_TYPING)
        self.hooks.on_typing(False)

    def _on_disconnect(self, message: Disconnect) -> None:
        """Either handler: advance the disconnect handshake to closure."""
        self._advance(Event.RECV_DISCONNECT)
        self.hooks.on_disconnect(message.reason)
        if self.state is State.DISCONNECTING:
            self._send(pdu.build_disconnect())
        self._close()

    def _on_error(self, message: Error) -> None:
        """Either handler: a peer-reported error closes the session."""
        self.hooks.on_error(message.code, message.desc)
        self._close()

    def _timeout(self, event: Event) -> None:
        """Apply a timeout event when it is legal in the current state."""
        if self.state is State.CLOSED:
            return
        self._advance(event)
        self._close()

    def _advance(self, event: Event) -> None:
        """Move the DFA forward, raising on any illegal transition."""
        self.state = transition(self.state, event)

    def _fail(self, exc: QCPError) -> None:
        """Emit an ERROR frame for a detected fault and close."""
        self._send(pdu.build_error(exc.error_code, exc.description))
        self._close()

    def _send(self, frame: bytes) -> None:
        """Write a frame to the transport unless already closed."""
        if self.state is State.CLOSED:
            return
        self.transport.send_bytes(frame)

    def _close(self) -> None:
        """Transition to CLOSED, tear down transport once, and notify observers."""
        if self._torn_down:
            return
        self._torn_down = True
        self.state = State.CLOSED
        self.transport.close()
        self.hooks.on_closed()

    _HANDLERS: ClassVar[dict[type, Callable[["Session", object], None]]] = {}


Session._HANDLERS = {
    LoginReq: Session._on_login_req,
    LoginOk: Session._on_login_ok,
    LoginFail: Session._on_login_fail,
    ChatMsg: Session._on_chat,
    Ack: Session._on_ack,
    TypingStart: Session._on_typing_start,
    TypingStop: Session._on_typing_stop,
    Disconnect: Session._on_disconnect,
}
