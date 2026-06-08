"""Protocol-wide enums and numeric constants for QCP."""

from enum import IntEnum

VERSION_1: int = 1
HEADER_SIZE: int = 8
MAX_PAYLOAD: int = 65535
BITS_PER_BYTE: int = 8

AUTH_TIMEOUT_SEC: float = 10.0
DISCONNECT_TIMEOUT_SEC: float = 5.0
IDLE_TIMEOUT_SEC: float = 60.0

MSG_TYPE_SIZE: int = 1
VERSION_SIZE: int = 1
SEQ_NUM_SIZE: int = 4
PAYLOAD_LEN_SIZE: int = 2

USERNAME_LEN_SIZE: int = 1
PASSWORD_LEN_SIZE: int = 1
TEXT_LEN_SIZE: int = 2
REASON_LEN_SIZE: int = 1
DESC_LEN_SIZE: int = 1
REASON_CODE_SIZE: int = 1
ERROR_CODE_SIZE: int = 1

MAX_UINT8: int = 255
SEQ_NUM_ZERO: int = 0
SEQ_NUM_START: int = 1

MAX_LOGIN_FAILS: int = 5
LOCK_WINDOW_SEC: float = 60.0

DEFAULT_PORT: int = 4433
ALPN_PROTOCOL: str = "qcp"
STREAM_ENCODING: str = "utf-8"


class MsgType(IntEnum):
    """Wire identifiers for every QCP message type."""

    LOGIN_REQ = 1
    LOGIN_OK = 2
    LOGIN_FAIL = 3
    CHAT_MSG = 4
    ACK = 5
    TYPING_START = 6
    TYPING_STOP = 7
    DISCONNECT = 8
    ERROR = 9


class FailReason(IntEnum):
    """Reason codes carried by a LOGIN_FAIL payload."""

    BAD_USER = 1
    BAD_PASSWORD = 2
    LOCKED = 3


class ErrorCode(IntEnum):
    """Error codes carried by an ERROR payload."""

    MALFORMED_PDU = 1
    UNSUPPORTED_VERSION = 2
    ILLEGAL_STATE = 3
    PROTOCOL_VIOLATION = 4


SEQ_BEARING_TYPES: frozenset[MsgType] = frozenset({MsgType.CHAT_MSG, MsgType.ACK})
