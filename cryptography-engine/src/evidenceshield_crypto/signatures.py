"""Digital signature module using Ed25519 and RFC 8785 Canonical JSON.

Enforces zero-trust key verification:
- Payloads are canonicalized to RFC 8785 bytes before signing/verifying.
- Signatures are 64-byte Ed25519 signatures.
- Verification keys MUST be looked up from an independently trusted key store;
  keys self-asserted within untrusted documents are rejected.
"""

import base64
from typing import Any, Mapping, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from evidenceshield_crypto.canonicalization import canonicalize_json
from evidenceshield_crypto.errors import (
    InvalidSignatureError,
    MissingRequiredInputError,
    UnsupportedFormatOrKeyError,
)
from evidenceshield_crypto.key_provider import KeyProvider


class TrustedKeyStore:
    """Store for independently trusted Ed25519 public verification keys."""

    def __init__(self, keys: Optional[Mapping[str, bytes]] = None):
        # Maps key_id -> 32-byte public key bytes
        self._keys: dict[str, bytes] = {}
        if keys:
            for kid, raw in keys.items():
                self.add_key(kid, raw)

    def add_key(self, key_id: str, public_key_bytes: bytes) -> None:
        """Register a trusted public key."""
        if len(public_key_bytes) != 32:
            raise ValueError(f"Ed25519 public key must be exactly 32 bytes, got {len(public_key_bytes)}")
        self._keys[key_id] = public_key_bytes

    def get_key(self, key_id: str) -> bytes:
        """Fetch trusted public key by versioned identifier."""
        if key_id not in self._keys:
            raise UnsupportedFormatOrKeyError(f"Untrusted or unregistered key reference: '{key_id}'")
        return self._keys[key_id]

    def has_key(self, key_id: str) -> bool:
        return key_id in self._keys


def sign_canonical_payload(
    payload: dict[str, Any],
    key_provider: KeyProvider,
    key_name: str,
    key_id: Optional[str] = None,
) -> dict[str, Any]:
    """Sign a dictionary payload by canonicalizing it and producing Ed25519 signature.

    Returns dict containing:
    - 'signature': base64-encoded signature string
    - 'key_id': versioned key identifier
    - 'canonical_bytes_len': length of signed canonical bytes
    """
    canonical_bytes = canonicalize_json(payload)
    raw_sig = key_provider.sign(canonical_bytes, key_name)
    b64_sig = base64.b64encode(raw_sig).decode("ascii")
    effective_key_id = key_id or f"vault://transit/keys/{key_name}"
    return {
        "signature": b64_sig,
        "key_id": effective_key_id,
        "canonical_bytes_len": len(canonical_bytes),
    }


def verify_canonical_payload(
    payload: dict[str, Any],
    signature_b64: str,
    key_id: str,
    trusted_keys: TrustedKeyStore,
) -> bool:
    """Verify digital signature over a dictionary payload against trusted key store.

    Fails closed:
    - If key_id is not in trusted_keys, raises UnsupportedFormatOrKeyError.
    - If signature is corrupted or invalid, raises InvalidSignatureError.
    """
    if not signature_b64:
        raise MissingRequiredInputError("signature", "Signature string is missing or empty")
    if not key_id:
        raise MissingRequiredInputError("key_id", "Key reference is missing")

    pub_bytes = trusted_keys.get_key(key_id)
    canonical_bytes = canonicalize_json(payload)

    try:
        raw_sig = base64.b64decode(signature_b64)
        if len(raw_sig) != 64:
            raise InvalidSignatureError("Ed25519 signature must be exactly 64 bytes")
    except Exception as e:
        if isinstance(e, InvalidSignatureError):
            raise
        raise InvalidSignatureError(f"Failed to decode base64 signature: {e}") from e

    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        public_key.verify(raw_sig, canonical_bytes)
        return True
    except InvalidSignature as e:
        raise InvalidSignatureError("Ed25519 signature verification failed") from e
