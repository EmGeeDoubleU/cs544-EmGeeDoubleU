"""DFA state enum, event enum, transition table, and transition validation."""

from enum import Enum, IntEnum

from qcp.errors import IllegalStateError


class State(IntEnum):
    """The five protocol states enforced on both endpoints."""

    INIT = 0
    AUTHENTICATING = 1
    CONNECTED = 2
    DISCONNECTING = 3
    CLOSED = 4


class Event(Enum):
    """Inputs that may drive a state transition."""

    SEND_LOGIN_REQ = "send_login_req"
    RECV_LOGIN_REQ = "recv_login_req"
    SEND_LOGIN_OK = "send_login_ok"
    SEND_LOGIN_FAIL = "send_login_fail"
    RECV_LOGIN_OK = "recv_login_ok"
    RECV_LOGIN_FAIL = "recv_login_fail"
    SEND_CHAT = "send_chat"
    RECV_CHAT = "recv_chat"
    SEND_ACK = "send_ack"
    RECV_ACK = "recv_ack"
    SEND_TYPING = "send_typing"
    RECV_TYPING = "recv_typing"
    SEND_DISCONNECT = "send_disconnect"
    RECV_DISCONNECT = "recv_disconnect"
    AUTH_TIMEOUT = "auth_timeout"
    IDLE_TIMEOUT = "idle_timeout"
    DISCONNECT_TIMEOUT = "disconnect_timeout"


_TRANSITIONS: dict[tuple[State, Event], State] = {
    (State.INIT, Event.SEND_LOGIN_REQ): State.AUTHENTICATING,
    (State.INIT, Event.RECV_LOGIN_REQ): State.INIT,
    (State.INIT, Event.SEND_LOGIN_OK): State.CONNECTED,
    (State.INIT, Event.SEND_LOGIN_FAIL): State.CLOSED,
    (State.INIT, Event.AUTH_TIMEOUT): State.CLOSED,
    (State.AUTHENTICATING, Event.RECV_LOGIN_OK): State.CONNECTED,
    (State.AUTHENTICATING, Event.RECV_LOGIN_FAIL): State.CLOSED,
    (State.AUTHENTICATING, Event.AUTH_TIMEOUT): State.CLOSED,
    (State.CONNECTED, Event.SEND_CHAT): State.CONNECTED,
    (State.CONNECTED, Event.RECV_CHAT): State.CONNECTED,
    (State.CONNECTED, Event.SEND_ACK): State.CONNECTED,
    (State.CONNECTED, Event.RECV_ACK): State.CONNECTED,
    (State.CONNECTED, Event.SEND_TYPING): State.CONNECTED,
    (State.CONNECTED, Event.RECV_TYPING): State.CONNECTED,
    (State.CONNECTED, Event.SEND_DISCONNECT): State.DISCONNECTING,
    (State.CONNECTED, Event.RECV_DISCONNECT): State.DISCONNECTING,
    (State.CONNECTED, Event.IDLE_TIMEOUT): State.DISCONNECTING,
    (State.DISCONNECTING, Event.SEND_DISCONNECT): State.DISCONNECTING,
    (State.DISCONNECTING, Event.RECV_DISCONNECT): State.CLOSED,
    (State.DISCONNECTING, Event.DISCONNECT_TIMEOUT): State.CLOSED,
}


def next_state(state: State, event: Event) -> State | None:
    """Return the destination state for an event, or None if it is illegal."""
    return _TRANSITIONS.get((state, event))


def transition(state: State, event: Event) -> State:
    """Apply a transition, raising IllegalStateError when it is not permitted."""
    destination = next_state(state, event)
    if destination is None:
        raise IllegalStateError(f"event {event.value} illegal in state {state.name}")
    return destination


def is_terminal(state: State) -> bool:
    """Report whether a state is the terminal CLOSED state."""
    return state is State.CLOSED
