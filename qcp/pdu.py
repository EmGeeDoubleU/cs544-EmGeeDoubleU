"""PDU dataclasses plus a build/parse pair per message type and a frame decoder."""

from dataclasses import dataclass
from typing import Callable

from qcp.codec import (
    decode_header,
    encode_header,
    read_lp_string,
    read_uint,
    write_lp_string,
    write_uint,
)
from qcp.constants import (
    DESC_LEN_SIZE,
    ERROR_CODE_SIZE,
    HEADER_SIZE,
    PASSWORD_LEN_SIZE,
    REASON_CODE_SIZE,
    REASON_LEN_SIZE,
    SEQ_BEARING_TYPES,
    SEQ_NUM_ZERO,
    TEXT_LEN_SIZE,
    USERNAME_LEN_SIZE,
    VERSION_1,
    MsgType,
)
from qcp.errors import MalformedPDUError, UnsupportedVersionError


@dataclass(frozen=True)
class LoginReq:
    """Client credentials offered to the server."""

    username: str
    password: str


@dataclass(frozen=True)
class LoginOk:
    """Server acceptance of a login request."""


@dataclass(frozen=True)
class LoginFail:
    """Server rejection of a login request with a reason code."""

    reason: int


@dataclass(frozen=True)
class ChatMsg:
    """A chat line carrying its own sequence number."""

    seq_num: int
    text: str


@dataclass(frozen=True)
class Ack:
    """Acknowledgement mirroring the sequence number of a chat line."""

    seq_num: int


@dataclass(frozen=True)
class TypingStart:
    """Notification that the peer began typing."""


@dataclass(frozen=True)
class TypingStop:
    """Notification that the peer stopped typing."""


@dataclass(frozen=True)
class Disconnect:
    """Request to tear down the session with an optional reason."""

    reason: str = ""


@dataclass(frozen=True)
class Error:
    """Protocol error notification with a code and optional description."""

    code: int
    desc: str = ""


def build_login_req(username: str, password: str) -> bytes:
    """Serialize a LOGIN_REQ frame."""
    payload = write_lp_string(username, USERNAME_LEN_SIZE) + write_lp_string(
        password, PASSWORD_LEN_SIZE
    )
    return _frame(MsgType.LOGIN_REQ, SEQ_NUM_ZERO, payload)


def build_login_ok() -> bytes:
    """Serialize a LOGIN_OK frame."""
    return _frame(MsgType.LOGIN_OK, SEQ_NUM_ZERO, b"")


def build_login_fail(reason: int) -> bytes:
    """Serialize a LOGIN_FAIL frame."""
    return _frame(MsgType.LOGIN_FAIL, SEQ_NUM_ZERO, write_uint(reason, REASON_CODE_SIZE))


def build_chat_msg(seq_num: int, text: str) -> bytes:
    """Serialize a CHAT_MSG frame carrying its sequence number."""
    return _frame(MsgType.CHAT_MSG, seq_num, write_lp_string(text, TEXT_LEN_SIZE))


def build_ack(seq_num: int) -> bytes:
    """Serialize an ACK frame mirroring a chat sequence number."""
    return _frame(MsgType.ACK, seq_num, b"")


def build_typing_start() -> bytes:
    """Serialize a TYPING_START frame."""
    return _frame(MsgType.TYPING_START, SEQ_NUM_ZERO, b"")


def build_typing_stop() -> bytes:
    """Serialize a TYPING_STOP frame."""
    return _frame(MsgType.TYPING_STOP, SEQ_NUM_ZERO, b"")


def build_disconnect(reason: str = "") -> bytes:
    """Serialize a DISCONNECT frame with an optional reason."""
    return _frame(MsgType.DISCONNECT, SEQ_NUM_ZERO, write_lp_string(reason, REASON_LEN_SIZE))


def build_error(code: int, desc: str = "") -> bytes:
    """Serialize an ERROR frame with a code and optional description."""
    payload = write_uint(code, ERROR_CODE_SIZE) + write_lp_string(desc, DESC_LEN_SIZE)
    return _frame(MsgType.ERROR, SEQ_NUM_ZERO, payload)


def _frame(msg_type: MsgType, seq_num: int, payload: bytes) -> bytes:
    """Prepend a valid header to a payload to form a complete frame."""
    header = encode_header(msg_type, VERSION_1, seq_num, len(payload))
    return header + payload


def parse_login_req(payload: bytes) -> LoginReq:
    """Parse a LOGIN_REQ payload into its dataclass."""
    username, offset = read_lp_string(payload, 0, USERNAME_LEN_SIZE)
    password, offset = read_lp_string(payload, offset, PASSWORD_LEN_SIZE)
    _ensure_consumed(payload, offset)
    return LoginReq(username, password)


def parse_login_ok(payload: bytes) -> LoginOk:
    """Parse an empty LOGIN_OK payload."""
    _ensure_empty(payload)
    return LoginOk()


def parse_login_fail(payload: bytes) -> LoginFail:
    """Parse a LOGIN_FAIL payload into its dataclass."""
    reason, offset = read_uint(payload, 0, REASON_CODE_SIZE)
    _ensure_consumed(payload, offset)
    return LoginFail(reason)


def parse_chat_msg(payload: bytes, seq_num: int) -> ChatMsg:
    """Parse a CHAT_MSG payload, attaching the header sequence number."""
    text, offset = read_lp_string(payload, 0, TEXT_LEN_SIZE)
    _ensure_consumed(payload, offset)
    return ChatMsg(seq_num, text)


def parse_ack(payload: bytes, seq_num: int) -> Ack:
    """Parse an empty ACK payload, attaching the header sequence number."""
    _ensure_empty(payload)
    return Ack(seq_num)


def parse_typing_start(payload: bytes) -> TypingStart:
    """Parse an empty TYPING_START payload."""
    _ensure_empty(payload)
    return TypingStart()


def parse_typing_stop(payload: bytes) -> TypingStop:
    """Parse an empty TYPING_STOP payload."""
    _ensure_empty(payload)
    return TypingStop()


def parse_disconnect(payload: bytes) -> Disconnect:
    """Parse a DISCONNECT payload into its dataclass."""
    reason, offset = read_lp_string(payload, 0, REASON_LEN_SIZE)
    _ensure_consumed(payload, offset)
    return Disconnect(reason)


def parse_error(payload: bytes) -> Error:
    """Parse an ERROR payload into its dataclass."""
    code, offset = read_uint(payload, 0, ERROR_CODE_SIZE)
    desc, offset = read_lp_string(payload, offset, DESC_LEN_SIZE)
    _ensure_consumed(payload, offset)
    return Error(code, desc)


def parse_frame(frame: bytes) -> object:
    """Validate a complete frame and dispatch to the matching payload parser."""
    msg_type, version, seq_num, payload_len = decode_header(frame)
    _check_version(version)
    parser = _payload_parser(msg_type)
    payload = frame[HEADER_SIZE:]
    _check_payload_len(payload, payload_len)
    if msg_type in SEQ_BEARING_TYPES:
        return parser(payload, seq_num)
    return parser(payload)


def _check_version(version: int) -> None:
    """Reject any version other than the single supported one."""
    if version != VERSION_1:
        raise UnsupportedVersionError(f"unsupported version {version}")


def _check_payload_len(payload: bytes, declared: int) -> None:
    """Reject frames whose declared payload length disagrees with the bytes."""
    if len(payload) != declared:
        raise MalformedPDUError("payload length mismatch")


def _payload_parser(msg_type: int) -> Callable[..., object]:
    """Return the payload parser registered for a defined message type."""
    parser = _PARSERS.get(msg_type)
    if parser is None:
        raise MalformedPDUError(f"undefined message type {msg_type}")
    return parser


def _ensure_consumed(payload: bytes, offset: int) -> None:
    """Reject trailing bytes left after a payload was fully parsed."""
    if offset != len(payload):
        raise MalformedPDUError("unexpected trailing payload bytes")


def _ensure_empty(payload: bytes) -> None:
    """Reject any payload bytes for a message type that carries none."""
    if payload:
        raise MalformedPDUError("payload present where none expected")


_PARSERS: dict[MsgType, Callable[..., object]] = {
    MsgType.LOGIN_REQ: parse_login_req,
    MsgType.LOGIN_OK: parse_login_ok,
    MsgType.LOGIN_FAIL: parse_login_fail,
    MsgType.CHAT_MSG: parse_chat_msg,
    MsgType.ACK: parse_ack,
    MsgType.TYPING_START: parse_typing_start,
    MsgType.TYPING_STOP: parse_typing_stop,
    MsgType.DISCONNECT: parse_disconnect,
    MsgType.ERROR: parse_error,
}
