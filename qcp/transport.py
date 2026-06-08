"""Async QUIC plumbing shared by the client and server endpoints."""

import asyncio
from typing import Callable, Optional

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.quic.events import ConnectionTerminated, QuicEvent, StreamDataReceived

from qcp.codec import FrameBuffer
from qcp.constants import AUTH_TIMEOUT_SEC, DISCONNECT_TIMEOUT_SEC, IDLE_TIMEOUT_SEC
from qcp.session import Session
from qcp.state import State

TIMER_AUTH = "auth"
TIMER_IDLE = "idle"
TIMER_DISCONNECT = "disconnect"


class TimerSet:
    """Manages named single-shot asyncio timers for bounded protocol waits."""

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        """Bind the timer set to an event loop."""
        self._loop: asyncio.AbstractEventLoop = loop
        self._handles: dict[str, asyncio.TimerHandle] = {}

    def arm(self, name: str, delay: float, callback: Callable[[], None]) -> None:
        """Schedule a callback after a delay, replacing any prior timer of that name."""
        self.cancel(name)
        self._handles[name] = self._loop.call_later(delay, callback)

    def cancel(self, name: str) -> None:
        """Cancel a single named timer if it is armed."""
        handle = self._handles.pop(name, None)
        if handle is not None:
            handle.cancel()

    def cancel_all(self) -> None:
        """Cancel every armed timer."""
        self._cancel_handles(list(self._handles.values()))
        self._handles.clear()

    def _cancel_handles(self, handles: list[asyncio.TimerHandle]) -> None:
        """Cancel a batch of timer handles."""
        for handle in handles:
            handle.cancel()


class StreamTransport:
    """Adapts a QUIC bidirectional stream to the session Transport interface."""

    def __init__(self, protocol: "QcpProtocol", stream_id: int) -> None:
        """Bind the transport to one protocol instance and stream id."""
        self._protocol: "QcpProtocol" = protocol
        self._stream_id: int = stream_id

    def send_bytes(self, data: bytes) -> None:
        """Write frame bytes onto the stream and flush them to the network."""
        self._protocol._quic.send_stream_data(self._stream_id, data)
        self._protocol.transmit()

    def close(self) -> None:
        """Close the underlying QUIC connection."""
        self._protocol.close()
        self._protocol.transmit()


class QcpProtocol(QuicConnectionProtocol):
    """Base protocol that routes stream bytes into a session and runs timers."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        """Initialize buffers, timers, and the connection-closed event."""
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._session: Optional[Session] = None
        self._stream_id: Optional[int] = None
        self._buffer: FrameBuffer = FrameBuffer()
        self._timers: TimerSet = TimerSet(asyncio.get_event_loop())
        self.closed_event: asyncio.Event = asyncio.Event()

    def bind_session(self, session: Session, stream_id: int) -> None:
        """Attach a session and its stream, then arm the initial timer."""
        self._session = session
        self._stream_id = stream_id
        self._manage_timers()

    def note_activity(self) -> None:
        """Re-evaluate timers after an externally initiated session action."""
        self._manage_timers()

    def quic_event_received(self, event: QuicEvent) -> None:
        """Dispatch QUIC events to stream ingestion or termination handling."""
        if isinstance(event, StreamDataReceived):
            self._ingest(event.stream_id, event.data)
        elif isinstance(event, ConnectionTerminated):
            self._on_terminated()

    def _ingest(self, stream_id: int, data: bytes) -> None:
        """Feed received bytes through the framer into the bound session."""
        self._ensure_session(stream_id)
        if self._session is None:
            return
        self._buffer.feed(data)
        self._drain()
        self._manage_timers()

    def _ensure_session(self, stream_id: int) -> None:
        """Hook for subclasses to lazily create a session on first data."""

    def _drain(self) -> None:
        """Deliver every fully buffered frame to the session in order."""
        frame = self._buffer.pop_frame()
        while frame is not None:
            self._session.receive(frame)  # type: ignore[union-attr]
            frame = self._buffer.pop_frame()

    def _on_terminated(self) -> None:
        """Abort the session and signal closure when the connection drops."""
        if self._session is not None:
            self._session.abort()
        self._timers.cancel_all()
        self.closed_event.set()

    def _manage_timers(self) -> None:
        """Arm the timer appropriate to the session's current state."""
        if self._session is None:
            return
        self._timers.cancel_all()
        self._ARM_BY_STATE.get(self._session.state, type(self)._enter_closed)(self)

    def _arm_auth(self) -> None:
        """Bound the wait for authentication to complete."""
        self._timers.arm(TIMER_AUTH, AUTH_TIMEOUT_SEC, self._fire_auth)

    def _arm_idle(self) -> None:
        """Bound the idle period allowed while connected."""
        self._timers.arm(TIMER_IDLE, IDLE_TIMEOUT_SEC, self._fire_idle)

    def _arm_disconnect(self) -> None:
        """Bound the wait for a disconnect reply."""
        self._timers.arm(TIMER_DISCONNECT, DISCONNECT_TIMEOUT_SEC, self._fire_disconnect)

    def _enter_closed(self) -> None:
        """Cancel timers and tear the connection down on closure."""
        self._timers.cancel_all()
        self.closed_event.set()
        self.close()

    def _fire_auth(self) -> None:
        """Deliver an authentication timeout to the session."""
        self._session.on_auth_timeout()  # type: ignore[union-attr]
        self._manage_timers()

    def _fire_idle(self) -> None:
        """Deliver an idle timeout to the session."""
        self._session.on_idle_timeout()  # type: ignore[union-attr]
        self._manage_timers()

    def _fire_disconnect(self) -> None:
        """Deliver a disconnect timeout to the session."""
        self._session.on_disconnect_timeout()  # type: ignore[union-attr]
        self._manage_timers()

    _ARM_BY_STATE: dict[State, Callable[["QcpProtocol"], None]] = {
        State.INIT: _arm_auth,
        State.AUTHENTICATING: _arm_auth,
        State.CONNECTED: _arm_idle,
        State.DISCONNECTING: _arm_disconnect,
    }
