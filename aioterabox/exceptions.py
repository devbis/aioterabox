class TeraboxApiError(Exception):
    """Base exception for Terabox API errors."""
    pass


class TeraboxUnauthorizedError(TeraboxApiError):
    """Exception for unauthorized access errors in Terabox API."""
    pass


class TeraboxNotFoundError(TeraboxApiError):
    """Exception for not found errors in Terabox API."""
    pass


class TeraboxChecksumMismatchError(TeraboxApiError):
    """Exception for checksum mismatch errors in Terabox API."""
    pass


class TeraboxContentTypeError(TeraboxApiError):
    """Exception for content type errors in Terabox API."""
    pass
