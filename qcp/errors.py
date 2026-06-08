"""QCP exception types mapped one-to-one to protocol ERROR codes."""

from qcp.constants import ErrorCode


class QCPError(Exception):
    """Base class for protocol faults that carry an ERROR code."""

    error_code: ErrorCode = ErrorCode.MALFORMED_PDU

    def __init__(self, description: str = "") -> None:
        """Store a short human-readable description alongside the code."""
        super().__init__(description)
        self.description: str = description


class MalformedPDUError(QCPError):
    """Raised when a frame cannot be parsed under the protocol grammar."""

    error_code: ErrorCode = ErrorCode.MALFORMED_PDU


class UnsupportedVersionError(QCPError):
    """Raised when a frame declares a VERSION other than the supported one."""

    error_code: ErrorCode = ErrorCode.UNSUPPORTED_VERSION


class IllegalStateError(QCPError):
    """Raised when a PDU arrives in a state that forbids it."""

    error_code: ErrorCode = ErrorCode.ILLEGAL_STATE


class ProtocolViolationError(QCPError):
    """Raised on semantic violations such as a stale or duplicate ACK."""

    error_code: ErrorCode = ErrorCode.PROTOCOL_VIOLATION
