"""Pure byte-level encode/decode helpers for headers and length-prefixed fields."""

from qcp.constants import (
    BITS_PER_BYTE,
    HEADER_SIZE,
    MSG_TYPE_SIZE,
    PAYLOAD_LEN_SIZE,
    SEQ_NUM_SIZE,
    STREAM_ENCODING,
    VERSION_SIZE,
)
from qcp.errors import MalformedPDUError

_BIG_ENDIAN = "big"


def write_uint(value: int, n_bytes: int) -> bytes:
    """Encode an unsigned integer into n big-endian bytes."""
    return value.to_bytes(n_bytes, _BIG_ENDIAN)


def read_uint(data: bytes, offset: int, n_bytes: int) -> tuple[int, int]:
    """Decode an unsigned integer of n bytes, returning value and next offset."""
    end = offset + n_bytes
    if end > len(data):
        raise MalformedPDUError("integer field exceeds buffer")
    return int.from_bytes(data[offset:end], _BIG_ENDIAN), end


def write_lp_string(text: str, len_bytes: int) -> bytes:
    """Encode a UTF-8 string with an n-byte big-endian length prefix."""
    encoded = text.encode(STREAM_ENCODING)
    max_len = (1 << (len_bytes * BITS_PER_BYTE)) - 1
    if len(encoded) > max_len:
        raise MalformedPDUError("string too long for its length prefix")
    return write_uint(len(encoded), len_bytes) + encoded


def read_lp_string(data: bytes, offset: int, len_bytes: int) -> tuple[str, int]:
    """Decode a length-prefixed UTF-8 string, returning text and next offset."""
    length, offset = read_uint(data, offset, len_bytes)
    end = offset + length
    if end > len(data):
        raise MalformedPDUError("string body exceeds buffer")
    return _decode_utf8(data[offset:end]), end


def _decode_utf8(raw: bytes) -> str:
    """Decode raw bytes as UTF-8 or fail as malformed."""
    try:
        return raw.decode(STREAM_ENCODING)
    except UnicodeDecodeError as exc:
        raise MalformedPDUError("invalid UTF-8 in string field") from exc


def encode_header(msg_type: int, version: int, seq_num: int, payload_len: int) -> bytes:
    """Encode the fixed 8-byte QCP header."""
    return (
        write_uint(msg_type, MSG_TYPE_SIZE)
        + write_uint(version, VERSION_SIZE)
        + write_uint(seq_num, SEQ_NUM_SIZE)
        + write_uint(payload_len, PAYLOAD_LEN_SIZE)
    )


def decode_header(data: bytes) -> tuple[int, int, int, int]:
    """Decode the fixed 8-byte header into (msg_type, version, seq_num, payload_len)."""
    if len(data) < HEADER_SIZE:
        raise MalformedPDUError("frame shorter than header")
    msg_type, offset = read_uint(data, 0, MSG_TYPE_SIZE)
    version, offset = read_uint(data, offset, VERSION_SIZE)
    seq_num, offset = read_uint(data, offset, SEQ_NUM_SIZE)
    payload_len, _ = read_uint(data, offset, PAYLOAD_LEN_SIZE)
    return msg_type, version, seq_num, payload_len


class FrameBuffer:
    """Reassembles stream bytes into complete header-delimited frames."""

    def __init__(self) -> None:
        """Start with an empty internal byte buffer."""
        self._buf: bytes = b""

    def feed(self, data: bytes) -> None:
        """Append newly received stream bytes to the buffer."""
        self._buf += data

    def pop_frame(self) -> bytes | None:
        """Return one complete frame if fully buffered, else None."""
        if len(self._buf) < HEADER_SIZE:
            return None
        _, _, _, payload_len = decode_header(self._buf)
        total = HEADER_SIZE + payload_len
        if len(self._buf) < total:
            return None
        frame, self._buf = self._buf[:total], self._buf[total:]
        return frame
