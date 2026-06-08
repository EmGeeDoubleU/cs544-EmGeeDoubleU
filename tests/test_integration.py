"""Integration and fuzz tests driving full sessions over an in-memory link."""

import random

from qcp import pdu
from qcp.codec import encode_header
from qcp.constants import ErrorCode, MsgType
from qcp.errors import QCPError
from qcp.session import Authenticator, Role, Session
from qcp.state import State
from tests.conftest import FakeTransport, Recorder, make_client, make_server, pump


def _connected_pair():
    """Return a client/server pair already authenticated and CONNECTED."""
    client, client_tx, client_rec = make_client()
    server, server_tx, server_rec = make_server()
    client.login("bob", "builder")
    pump(client, client_tx, server, server_tx)
    return (client, client_tx, client_rec), (server, server_tx, server_rec)


def test_successful_login_chat_ack_round_trip() -> None:
    """Login, then a chat and its acknowledgement, complete end to end."""
    (client, client_tx, client_rec), (server, server_tx, server_rec) = _connected_pair()
    assert client.state == State.CONNECTED
    assert server.state == State.CONNECTED
    seq = client.send_chat("hello")
    pump(client, client_tx, server, server_tx)
    assert server_rec.chats == [(seq, "hello")]
    assert client_rec.acks == [seq]


def test_graceful_disconnect_handshake() -> None:
    """A disconnect initiated by the client closes both endpoints."""
    (client, client_tx, _), (server, server_tx, server_rec) = _connected_pair()
    client.disconnect("bye")
    pump(client, client_tx, server, server_tx)
    assert client.state == State.CLOSED
    assert server.state == State.CLOSED
    assert server_rec.disconnects == ["bye"]


def test_chat_before_login_is_illegal_state() -> None:
    """A chat received before login yields ERROR code 3 and closure."""
    server, server_tx, _ = make_server()
    server.receive(pdu.build_chat_msg(1, "early"))
    assert server.state == State.CLOSED
    assert pdu.parse_frame(server_tx.outbox[-1]).code == ErrorCode.ILLEGAL_STATE


def test_unsupported_version_rejected() -> None:
    """A non-1 version yields ERROR code 2 and closure."""
    server, server_tx, _ = make_server()
    frame = bytearray(pdu.build_login_ok())
    frame[1] = 2
    server.receive(bytes(frame))
    assert server.state == State.CLOSED
    assert pdu.parse_frame(server_tx.outbox[-1]).code == ErrorCode.UNSUPPORTED_VERSION


def test_payload_length_mismatch_rejected() -> None:
    """A payload-length mismatch yields ERROR code 1 and closure."""
    server, server_tx, _ = make_server()
    frame = encode_header(MsgType.CHAT_MSG, 1, 1, 99) + b"tiny"
    server.receive(frame)
    assert server.state == State.CLOSED
    assert pdu.parse_frame(server_tx.outbox[-1]).code == ErrorCode.MALFORMED_PDU


def test_undefined_type_rejected() -> None:
    """An undefined message type yields ERROR code 1 and closure."""
    server, server_tx, _ = make_server()
    server.receive(encode_header(200, 1, 0, 0))
    assert server.state == State.CLOSED
    assert pdu.parse_frame(server_tx.outbox[-1]).code == ErrorCode.MALFORMED_PDU


def test_stale_or_duplicate_ack_rejected() -> None:
    """An ACK for a never-sent sequence yields ERROR code 4 and closure."""
    (client, client_tx, _), _ = _connected_pair()
    client.receive(pdu.build_ack(999))
    assert client.state == State.CLOSED
    assert pdu.parse_frame(client_tx.outbox[-1]).code == ErrorCode.PROTOCOL_VIOLATION


def test_duplicate_ack_after_valid_ack_rejected() -> None:
    """A second ACK for an already-acknowledged sequence is rejected."""
    (client, client_tx, _), (server, server_tx, _) = _connected_pair()
    seq = client.send_chat("hi")
    pump(client, client_tx, server, server_tx)
    client.receive(pdu.build_ack(seq))
    assert client.state == State.CLOSED
    assert pdu.parse_frame(client_tx.outbox[-1]).code == ErrorCode.PROTOCOL_VIOLATION


def test_login_fail_closes_connection() -> None:
    """Bad credentials drive a LOGIN_FAIL and close both endpoints."""
    client, client_tx, client_rec = make_client()
    server, server_tx, _ = make_server()
    client.login("bob", "wrong")
    pump(client, client_tx, server, server_tx)
    assert server.state == State.CLOSED
    assert client.state == State.CLOSED
    assert client_rec.login_fails == [2]
    assert server_tx.closed and client_tx.closed


def test_auth_timeout_closes_client() -> None:
    """An authentication timeout closes a waiting client."""
    client, _, _ = make_client()
    client.login("bob", "builder")
    assert client.state == State.AUTHENTICATING
    client.on_auth_timeout()
    assert client.state == State.CLOSED


def test_idle_timeout_starts_disconnect() -> None:
    """An idle timeout while connected sends a reasoned disconnect."""
    (client, client_tx, _), _ = _connected_pair()
    client.on_idle_timeout()
    assert client.state == State.DISCONNECTING
    assert pdu.parse_frame(client_tx.outbox[-1]) == pdu.Disconnect("idle timeout")


def test_disconnect_timeout_closes() -> None:
    """A disconnect timeout forces closure of a stalled handshake."""
    (client, _, _), _ = _connected_pair()
    client.disconnect("bye")
    assert client.state == State.DISCONNECTING
    client.on_disconnect_timeout()
    assert client.state == State.CLOSED


def test_account_lockout_after_repeated_failures() -> None:
    """Repeated bad passwords eventually lock the account with reason 3."""
    reasons = _collect_login_fail_reasons("bob", "nope", attempts=5)
    assert reasons[-1] == 3


def _collect_login_fail_reasons(username: str, password: str, attempts: int) -> list[int]:
    """Run repeated failing logins against fresh clients and gather reasons."""
    authenticator = Authenticator()
    return [_one_login_fail(username, password, authenticator) for _ in range(attempts)]


def _one_login_fail(username: str, password: str, authenticator: Authenticator) -> int:
    """Drive one failing login and return the reported reason code."""
    client, client_tx, client_rec = make_client()
    server_tx = FakeTransport()
    server_rec = Recorder()
    server = Session(Role.SERVER, server_tx, server_rec.hooks(), authenticator)
    client.login(username, password)
    pump(client, client_tx, server, server_tx)
    return client_rec.login_fails[-1]


def test_fuzz_parser_never_crashes() -> None:
    """Random bytes either parse to a PDU or raise a QCPError, never crash."""
    rng = random.Random(1337)
    _fuzz_iterations(rng, 4000)


def _fuzz_iterations(rng: random.Random, count: int) -> None:
    """Throw many random byte strings at the frame parser."""
    for _ in range(count):
        _assert_parse_is_safe(_random_bytes(rng))


def _random_bytes(rng: random.Random) -> bytes:
    """Build a random byte string of a random short length."""
    length = rng.randint(0, 40)
    return bytes(rng.randint(0, 255) for _ in range(length))


def _assert_parse_is_safe(raw: bytes) -> None:
    """Assert parse_frame only ever raises the protocol's own errors."""
    try:
        pdu.parse_frame(raw)
    except QCPError:
        return


def test_fuzz_session_never_crashes() -> None:
    """Feeding random frames to a live session never raises out."""
    rng = random.Random(7)
    _fuzz_session(rng, 2000)


def _fuzz_session(rng: random.Random, count: int) -> None:
    """Feed many random frames into a connected client session."""
    for _ in range(count):
        _feed_random_frame(rng)


def _feed_random_frame(rng: random.Random) -> None:
    """Deliver one random frame to a fresh connected client without crashing."""
    (client, _, _), _ = _connected_pair()
    client.receive(_random_bytes(rng))
