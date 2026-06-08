"""Shared test helpers: a fake transport and an in-memory session link."""

from dataclasses import dataclass, field

from qcp.session import Authenticator, Role, Session, SessionHooks


@dataclass
class FakeTransport:
    """In-memory transport that records outbound frames and closure."""

    outbox: list[bytes] = field(default_factory=list)
    closed: bool = False

    def send_bytes(self, data: bytes) -> None:
        """Record a frame the session asked to send."""
        self.outbox.append(data)

    def close(self) -> None:
        """Mark the transport as torn down."""
        self.closed = True


@dataclass
class Recorder:
    """Collects session events for assertions in tests."""

    chats: list[tuple[int, str]] = field(default_factory=list)
    acks: list[int] = field(default_factory=list)
    typing: list[bool] = field(default_factory=list)
    logins_ok: int = 0
    login_fails: list[int] = field(default_factory=list)
    errors: list[tuple[int, str]] = field(default_factory=list)
    disconnects: list[str] = field(default_factory=list)
    closed: int = 0

    def hooks(self) -> SessionHooks:
        """Build a SessionHooks bound to this recorder."""
        return SessionHooks(
            on_login_ok=self._on_login_ok,
            on_login_fail=self.login_fails.append,
            on_chat=lambda seq, text: self.chats.append((seq, text)),
            on_ack=self.acks.append,
            on_typing=self.typing.append,
            on_disconnect=self.disconnects.append,
            on_error=lambda code, desc: self.errors.append((code, desc)),
            on_closed=self._on_closed,
        )

    def _on_login_ok(self) -> None:
        """Count a successful login event."""
        self.logins_ok += 1

    def _on_closed(self) -> None:
        """Count a session-closed event."""
        self.closed += 1


def deliver(src: FakeTransport, dst: Session) -> int:
    """Feed every queued frame from a transport into a peer session."""
    frames = list(src.outbox)
    src.outbox.clear()
    _feed_all(frames, dst)
    return len(frames)


def _feed_all(frames: list[bytes], dst: Session) -> None:
    """Deliver a batch of frames to a session in order."""
    for frame in frames:
        dst.receive(frame)


def pump(client: Session, client_tx: FakeTransport, server: Session, server_tx: FakeTransport) -> None:
    """Exchange frames between two sessions until both queues drain."""
    while deliver(client_tx, server) + deliver(server_tx, client) > 0:
        pass


def make_server() -> tuple[Session, FakeTransport, Recorder]:
    """Build a server session with an authenticator and recorder."""
    tx = FakeTransport()
    rec = Recorder()
    session = Session(Role.SERVER, tx, rec.hooks(), Authenticator())
    return session, tx, rec


def make_client() -> tuple[Session, FakeTransport, Recorder]:
    """Build a client session with a recorder."""
    tx = FakeTransport()
    rec = Recorder()
    session = Session(Role.CLIENT, tx, rec.hooks())
    return session, tx, rec
