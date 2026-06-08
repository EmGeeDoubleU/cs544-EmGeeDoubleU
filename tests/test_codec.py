"""Unit tests for the pure codec layer."""

import pytest

from qcp.codec import (
    FrameBuffer,
    decode_header,
    encode_header,
    read_lp_string,
    read_uint,
    write_lp_string,
    write_uint,
)
from qcp.constants import HEADER_SIZE, MsgType
from qcp.errors import MalformedPDUError


def test_uint_round_trip() -> None:
    """A written unsigned integer decodes back to the same value and offset."""
    encoded = write_uint(258, 4)
    value, offset = read_uint(encoded, 0, 4)
    assert value == 258
    assert offset == 4


def test_read_uint_out_of_bounds() -> None:
    """Reading past the buffer raises a malformed-PDU error."""
    with pytest.raises(MalformedPDUError):
        read_uint(b"\x01", 0, 4)


def test_lp_string_round_trip() -> None:
    """A length-prefixed string decodes back to the same text and offset."""
    encoded = write_lp_string("héllo", 2)
    text, offset = read_lp_string(encoded, 0, 2)
    assert text == "héllo"
    assert offset == len(encoded)


def test_lp_string_too_long_for_prefix() -> None:
    """A string longer than its prefix can express is rejected."""
    with pytest.raises(MalformedPDUError):
        write_lp_string("x" * 256, 1)


def test_lp_string_bad_utf8() -> None:
    """Invalid UTF-8 in a string body is rejected as malformed."""
    raw = write_uint(2, 1) + b"\xff\xfe"
    with pytest.raises(MalformedPDUError):
        read_lp_string(raw, 0, 1)


def test_header_round_trip() -> None:
    """The header encodes and decodes its four fields losslessly."""
    encoded = encode_header(MsgType.CHAT_MSG, 1, 7, 12)
    assert len(encoded) == HEADER_SIZE
    assert decode_header(encoded) == (MsgType.CHAT_MSG, 1, 7, 12)


def test_decode_header_too_short() -> None:
    """A buffer shorter than the header is rejected."""
    with pytest.raises(MalformedPDUError):
        decode_header(b"\x01\x01")


def test_frame_buffer_splits_concatenated_frames() -> None:
    """The frame buffer yields each complete frame and withholds partials."""
    frame_a = encode_header(MsgType.ACK, 1, 1, 0)
    frame_b = encode_header(MsgType.ACK, 1, 2, 0)
    buf = FrameBuffer()
    buf.feed(frame_a + frame_b[:3])
    assert buf.pop_frame() == frame_a
    assert buf.pop_frame() is None
    buf.feed(frame_b[3:])
    assert buf.pop_frame() == frame_b
