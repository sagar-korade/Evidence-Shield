"""Machine-readable cryptographic and verification error definitions.

All errors defined here adhere strictly to EvidenceShield AI shared contract
specifications and fail-closed security principles.
"""

from enum import Enum
from typing import Any, Optional


class ErrorCode(str, Enum):
    """Machine-readable error codes required by EvidenceShield contracts."""
    CIPHERTEXT_AUTH_FAILED = "CIPHERTEXT_AUTH_FAILED"
    PLAINTEXT_DIGEST_MISMATCH = "PLAINTEXT_DIGEST_MISMATCH"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    INVALID_INCLUSION_PROOF = "INVALID_INCLUSION_PROOF"
    INVALID_CONSISTENCY_PROOF = "INVALID_CONSISTENCY_PROOF"
    UNSUPPORTED_FORMAT_OR_KEY = "UNSUPPORTED_FORMAT_OR_KEY"
    MISSING_REQUIRED_INPUT = "MISSING_REQUIRED_INPUT"
    ANCHOR_VERIFICATION_FAILED = "ANCHOR_VERIFICATION_FAILED"
    PENDING_ANCHOR = "PENDING_ANCHOR"


class EvidenceCryptoError(Exception):
    """Base exception for all EvidenceShield cryptographic failures."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(f"[{code.value}] {message}")
        self.code = code
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        """Serialize error to standardized machine-readable payload."""
        return {
            "error_code": self.code.value,
            "message": self.message,
            "details": self.details,
        }


class CiphertextAuthFailedError(EvidenceCryptoError):
    """Raised when AES-GCM authentication tag verification fails."""

    def __init__(self, message: str = "Ciphertext authentication tag verification failed", details: Optional[dict[str, Any]] = None):
        super().__init__(ErrorCode.CIPHERTEXT_AUTH_FAILED, message, details)


class PlaintextDigestMismatchError(EvidenceCryptoError):
    """Raised when recomputed SHA-256 does not match original digest."""

    def __init__(self, expected: str, actual: str, details: Optional[dict[str, Any]] = None):
        d = details or {}
        d.update({"expected_digest": expected, "actual_digest": actual})
        super().__init__(
            ErrorCode.PLAINTEXT_DIGEST_MISMATCH,
            f"Plaintext SHA-256 digest mismatch (expected: {expected}, actual: {actual})",
            d,
        )


class InvalidSignatureError(EvidenceCryptoError):
    """Raised when Ed25519 or checkpoint digital signature is invalid."""

    def __init__(self, message: str = "Signature verification failed", details: Optional[dict[str, Any]] = None):
        super().__init__(ErrorCode.INVALID_SIGNATURE, message, details)


class InvalidInclusionProofError(EvidenceCryptoError):
    """Raised when Merkle leaf inclusion proof fails to verify."""

    def __init__(self, message: str = "Merkle inclusion proof does not evaluate to expected root", details: Optional[dict[str, Any]] = None):
        super().__init__(ErrorCode.INVALID_INCLUSION_PROOF, message, details)


class InvalidConsistencyProofError(EvidenceCryptoError):
    """Raised when Merkle tree consistency proof between sizes fails."""

    def __init__(self, message: str = "Merkle consistency proof between tree sizes failed", details: Optional[dict[str, Any]] = None):
        super().__init__(ErrorCode.INVALID_CONSISTENCY_PROOF, message, details)


class UnsupportedFormatOrKeyError(EvidenceCryptoError):
    """Raised when a format version or key reference cannot be resolved."""

    def __init__(self, message: str = "Unsupported format or key reference", details: Optional[dict[str, Any]] = None):
        super().__init__(ErrorCode.UNSUPPORTED_FORMAT_OR_KEY, message, details)


class MissingRequiredInputError(EvidenceCryptoError):
    """Raised when mandatory cryptographic inputs are missing."""

    def __init__(self, field_name: str, message: Optional[str] = None, details: Optional[dict[str, Any]] = None):
        d = details or {}
        d["missing_field"] = field_name
        msg = message or f"Missing required cryptographic input field: '{field_name}'"
        super().__init__(ErrorCode.MISSING_REQUIRED_INPUT, msg, d)


class AnchorVerificationFailedError(EvidenceCryptoError):
    """Raised when on-chain anchor verification does not match checkpoint root."""

    def __init__(self, message: str = "Anchor smart contract verification failed", details: Optional[dict[str, Any]] = None):
        super().__init__(ErrorCode.ANCHOR_VERIFICATION_FAILED, message, details)


class PendingAnchorError(EvidenceCryptoError):
    """Raised when anchoring transaction is still pending confirmation."""

    def __init__(self, message: str = "On-chain anchor is pending confirmation", details: Optional[dict[str, Any]] = None):
        super().__init__(ErrorCode.PENDING_ANCHOR, message, details)
