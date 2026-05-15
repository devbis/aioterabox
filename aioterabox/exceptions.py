from dataclasses import dataclass, field
from typing import Any


class TeraboxApiError(Exception):
    """Base exception for Terabox API errors."""
    pass


class TeraboxUnauthorizedError(TeraboxApiError):
    """Exception for unauthorized access errors in Terabox API."""
    pass


@dataclass(slots=True)
class TeraboxLoginChallenge:
    """Structured login challenge returned by the TeraBox anti-bot flow."""

    challenge_type: str
    message: str
    url: str
    referrer: str
    session: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


class TeraboxLoginChallengeRequired(TeraboxUnauthorizedError):
    """Raised when login requires an explicit challenge continuation step."""

    def __init__(self, challenge: TeraboxLoginChallenge):
        super().__init__(challenge.message)
        self.challenge = challenge


class TeraboxNotFoundError(TeraboxApiError):
    """Exception for not found errors in Terabox API."""
    pass


class TeraboxChecksumMismatchError(TeraboxApiError):
    """Exception for checksum mismatch errors in Terabox API."""
    pass


class TeraboxContentTypeError(TeraboxApiError):
    """Exception for content type errors in Terabox API."""
    pass
