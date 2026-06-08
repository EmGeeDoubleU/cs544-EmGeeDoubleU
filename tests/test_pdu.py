"""Unit tests for PDU build/parse round trips and frame validation."""

import pytest

from qcp.codec import encode_header
from qcp.constants import ErrorCode, FailReason, MsgType
from qcp.errors import MalformedPDUError, UnsupportedVersionError
from qcp.pdu import (
    Ack,
    ChatMsg,
    Disconnect,
    Error,
    LoginFail,
    LoginOk,
    LoginReq,
    TypingStart,
    build_ack,
    build_chat_msg,
    build_disconnect,
    build_error,
    build_login_fail,
    build_login_ok,
    build_login_req,
    build_typing_start,
    parse_frame,
)


def test_login_req_round_trip() -> None:
    """A LOGIN_REQ frame parses back to its username and password."""
    assert parse_frame(build_login_req("bob", "builder")) == LoginReq("bob", "builder")


def test_login_ok_round_trip() -> None:
    """A LOGIN_OK frame parses back to an empty dataclass."""
    assert parse_frame(build_login_ok()) == LoginOk()


def test_login_fail_round_trip() -> None:
    """A LOGIN_FAIL frame preserves its reason code."""
    assert parse_frame(build_login_fail(FailReason.LOCKED)) == LoginFail(FailReason.LOCKED)


def test_chat_msg_round_trip() -> None:
    """A CHAT_MSG frame preserves its sequence number and text."""
    assert parse_frame(build_chat_msg(5, "hi")) == ChatMsg(5, "hi")


def test_ack_round_trip() -> None:
    """An ACK frame preserves the mirrored sequence number."""
    assert parse_frame(build_ack(9)) == Ack(9)


def test_typing_round_trip() -> None:
    """A TYPING_START frame parses back to an empty dataclass."""
    assert parse_frame(build_typing_start()) == TypingStart()


def test_disconnect_round_trip() -> None:
    """A DISCONNECT frame preserves its optional reason text."""
    assert parse_frame(build_disconnect("bye")) == Disconnect("bye")


def test_error_round_trip() -> None:
    """An ERROR frame preserves its code and description."""
    assert parse_frame(build_error(ErrorCode.ILLEGAL_STATE, "nope")) == Error(
        ErrorCode.ILLEGAL_STATE, "nope"
    )


def test_unsupported_version_rejected() -> None:
    """A non-1 version yields an unsupported-version error."""
    frame = bytearray(build_login_ok())
    frame[1] = 2
    with pytest.raises(UnsupportedVersionError):
        parse_frame(bytes(frame))


def test_undefined_message_type_rejected() -> None:
    """An undefined message type is treated as malformed."""
    frame = encode_header(99, 1, 0, 0)
    with pytest.raises(MalformedPDUError):
        parse_frame(frame)


def test_payload_length_mismatch_rejected() -> None:
    """A declared payload length that disagrees with the bytes is malformed."""
    frame = encode_header(MsgType.CHAT_MSG, 1, 1, 50) + b"short"
    with pytest.raises(MalformedPDUError):
        parse_frame(frame)


def test_trailing_payload_bytes_rejected() -> None:
    """Extra bytes after a fully parsed payload are malformed."""
    frame = encode_header(MsgType.LOGIN_OK, 1, 0, 3) + b"abc"
    with pytest.raises(MalformedPDUError):
        parse_frame(frame)
