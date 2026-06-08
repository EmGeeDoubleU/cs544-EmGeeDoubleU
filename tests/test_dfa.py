"""Unit tests for the state-machine transition table."""

import pytest

from qcp.errors import IllegalStateError
from qcp.state import Event, State, is_terminal, next_state, transition


def test_login_handshake_path() -> None:
    """The client login path walks INIT to AUTHENTICATING to CONNECTED."""
    state = transition(State.INIT, Event.SEND_LOGIN_REQ)
    assert state == State.AUTHENTICATING
    assert transition(state, Event.RECV_LOGIN_OK) == State.CONNECTED


def test_login_fail_closes() -> None:
    """A LOGIN_FAIL while authenticating moves to CLOSED."""
    assert transition(State.AUTHENTICATING, Event.RECV_LOGIN_FAIL) == State.CLOSED


def test_server_accept_path() -> None:
    """The server accept path walks INIT to CONNECTED via SEND_LOGIN_OK."""
    assert transition(State.INIT, Event.RECV_LOGIN_REQ) == State.INIT
    assert transition(State.INIT, Event.SEND_LOGIN_OK) == State.CONNECTED


def test_chat_keeps_connected() -> None:
    """Chat, ack, and typing events keep the session CONNECTED."""
    assert transition(State.CONNECTED, Event.SEND_CHAT) == State.CONNECTED
    assert transition(State.CONNECTED, Event.RECV_ACK) == State.CONNECTED
    assert transition(State.CONNECTED, Event.RECV_TYPING) == State.CONNECTED


def test_disconnect_handshake() -> None:
    """A disconnect exchange walks CONNECTED to DISCONNECTING to CLOSED."""
    state = transition(State.CONNECTED, Event.SEND_DISCONNECT)
    assert state == State.DISCONNECTING
    assert transition(state, Event.RECV_DISCONNECT) == State.CLOSED


def test_timeouts_reach_terminal_states() -> None:
    """Each bounded-wait timeout drives the session toward CLOSED."""
    assert transition(State.AUTHENTICATING, Event.AUTH_TIMEOUT) == State.CLOSED
    assert transition(State.CONNECTED, Event.IDLE_TIMEOUT) == State.DISCONNECTING
    assert transition(State.DISCONNECTING, Event.DISCONNECT_TIMEOUT) == State.CLOSED


def test_chat_while_authenticating_is_illegal() -> None:
    """A chat event while authenticating has no legal transition."""
    assert next_state(State.AUTHENTICATING, Event.RECV_CHAT) is None
    with pytest.raises(IllegalStateError):
        transition(State.AUTHENTICATING, Event.RECV_CHAT)


def test_login_req_while_connected_is_illegal() -> None:
    """Receiving a login request while connected is illegal."""
    with pytest.raises(IllegalStateError):
        transition(State.CONNECTED, Event.RECV_LOGIN_REQ)


def test_is_terminal() -> None:
    """Only CLOSED is reported as terminal."""
    assert is_terminal(State.CLOSED)
    assert not is_terminal(State.CONNECTED)
