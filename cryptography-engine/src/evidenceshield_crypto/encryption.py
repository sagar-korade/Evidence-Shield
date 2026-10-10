"""Authenticated Encryption and Decryption module (AES-256-GCM).

Adheres to zero-trust pipeline:
1. Fresh 256-bit DEK generated per immutable version.
2. Fresh 96-bit nonce.
3. Canonical AAD binding case_id, document_id, version_id, format, digest.
4. AES-256-GCM encryption with 128-bit authentication tag.
5. Vault Transit DEK wrapping.
6. Fail-closed decryption pipeline with strict error demarcation:
   - CiphertextAuthFailedError on GCM tag verification failure.
   - PlaintextDigestMismatchError on recomputed SHA-256 mismatch.
   - UnsupportedFormatOrKeyError on key wrapping / unwrap failure.
   - MissingRequiredInputError on missing mandatory fields.
"""

import base64
import os
from dataclasses import dataclass
from typing import Any, Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from evidenceshield_crypto.canonicalization import canonicalize_json
from evidenceshield_crypto.errors import (
    CiphertextAuthFailedError,
    MissingRequiredInputError,
    PlaintextDigestMismatchError,
    UnsupportedFormatOrKeyError,
)
from evidenceshield_crypto.hashing import compute_sha256_bytes
from evidenceshield_crypto.key_provider import KeyProvider

ENCRYPTION_FORMAT_V1 = "evidenceshield-v1-aes256gcm"


def build_canonical_aad(
    case_id: str,
    document_id: str,
    version_id: str,
    digest: str,
    format_name: str = ENCRYPTION_FORMAT_V1,
) -> bytes:
    """Construct RFC 8785 canonical AAD binding all core identifiers."""
    aad_obj = {
        "case_id": case_id,
        "document_id": document_id,
        "format": format_name,
        "original_digest": digest.lower(),
        "version_id": version_id,
    }
    return canonicalize_json(aad_obj)


@dataclass(frozen=True)
class EncryptedPackage:
    """Immutable envelope containing encrypted artifact and metadata."""
    case_id: str
    document_id: str
    version_id: str
    state: str
    digest: str
    format: str
    key_name: str
    wrapped_key: str
    nonce: bytes        # 12 bytes
    tag: bytes          # 16 bytes
    ciphertext: bytes   # pure ciphertext (excluding tag)

    def to_metadata_dict(self) -> dict[str, Any]:
        """Convert metadata to dictionary for serialization."""
        return {
            "case_id": self.case_id,
            "document_id": self.document_id,
            "version_id": self.version_id,
            "state": self.state,
            "digest": self.digest,
            "format": self.format,
            "key_name": self.key_name,
            "wrapped_key": self.wrapped_key,
            "nonce_hex": self.nonce.hex(),
            "tag_hex": self.tag.hex(),
            "ciphertext_len": len(self.ciphertext),
        }


def encrypt_evidence_bytes(
    original_bytes: bytes,
    case_id: str,
    document_id: str,
    version_id: str,
    key_provider: KeyProvider,
    key_name: str,
    state: str = "INGESTED",
    format_name: str = ENCRYPTION_FORMAT_V1,
) -> EncryptedPackage:
    """Execute authenticated encryption pipeline for an immutable evidence version.

    1. Computes SHA-256 over exact original bytes.
    2. Generates fresh 256-bit cryptographically secure DEK.
    3. Generates unique 96-bit nonce.
    4. Builds canonical AAD binding identifiers.
    5. Encrypts using AES-256-GCM.
    6. Wraps DEK using KeyProvider (Vault Transit).
    7. Returns EncryptedPackage.
    """
    if not case_id:
        raise MissingRequiredInputError("case_id")
    if not document_id:
        raise MissingRequiredInputError("document_id")
    if not version_id:
        raise MissingRequiredInputError("version_id")

    # Step 1: Compute SHA-256
    digest = compute_sha256_bytes(original_bytes)

    # Step 2: Generate fresh 256-bit DEK
    dek = os.urandom(32)

    try:
        # Step 3: Generate unique 96-bit nonce
        nonce = os.urandom(12)

        # Step 4: Build exact canonical AAD
        aad = build_canonical_aad(
            case_id=case_id,
            document_id=document_id,
            version_id=version_id,
            digest=digest,
            format_name=format_name,
        )

        # Step 5: AES-256-GCM encrypt
        aesgcm = AESGCM(dek)
        # Python cryptography AESGCM appends 16-byte tag to ciphertext
        encrypted_raw = aesgcm.encrypt(nonce, original_bytes, aad)
        ciphertext = encrypted_raw[:-16]
        tag = encrypted_raw[-16:]

        # Step 6: Wrap DEK via KeyProvider
        wrapped_key = key_provider.wrap_key(dek, key_name)

        return EncryptedPackage(
            case_id=case_id,
            document_id=document_id,
            version_id=version_id,
            state=state,
            digest=digest,
            format=format_name,
            key_name=key_name,
            wrapped_key=wrapped_key,
            nonce=nonce,
            tag=tag,
            ciphertext=ciphertext,
        )
    finally:
        # Minimize plaintext key lifetime
        del dek


def decrypt_and_verify_evidence(
    package: Union[EncryptedPackage, dict[str, Any]],
    ciphertext_bytes: Optional[bytes],
    key_provider: KeyProvider,
) -> bytes:
    """Authenticated decryption and fail-closed integrity verification pipeline.

    Order of operations:
    1. Input validation & extraction.
    2. Unwrap DEK via KeyProvider.
    3. Reconstruct exact canonical AAD.
    4. AES-256-GCM authentication and decryption. Raises CiphertextAuthFailedError if invalid.
    5. Plaintext SHA-256 recomputation and digest comparison. Raises PlaintextDigestMismatchError if mismatch.
    6. Returns verified plaintext. Never returns partial or unauthenticated plaintext.
    """
    if isinstance(package, EncryptedPackage):
        case_id = package.case_id
        document_id = package.document_id
        version_id = package.version_id
        expected_digest = package.digest
        format_name = package.format
        key_name = package.key_name
        wrapped_key = package.wrapped_key
        nonce = package.nonce
        tag = package.tag
        cipher = package.ciphertext if ciphertext_bytes is None else ciphertext_bytes
    elif isinstance(package, dict):
        for req_field in ["case_id", "document_id", "version_id", "digest", "key_name", "wrapped_key"]:
            if req_field not in package or not package[req_field]:
                raise MissingRequiredInputError(req_field)
        case_id = package["case_id"]
        document_id = package["document_id"]
        version_id = package["version_id"]
        expected_digest = package["digest"]
        format_name = package.get("format", ENCRYPTION_FORMAT_V1)
        key_name = package["key_name"]
        wrapped_key = package["wrapped_key"]

        if "nonce" in package:
            nonce = package["nonce"]
        elif "nonce_hex" in package:
            nonce = bytes.fromhex(package["nonce_hex"])
        else:
            raise MissingRequiredInputError("nonce")

        if "tag" in package:
            tag = package["tag"]
        elif "tag_hex" in package:
            tag = bytes.fromhex(package["tag_hex"])
        else:
            raise MissingRequiredInputError("tag")

        if ciphertext_bytes is not None:
            cipher = ciphertext_bytes
        elif "ciphertext" in package:
            cipher = package["ciphertext"]
            if isinstance(cipher, str):
                cipher = base64.b64decode(cipher)
        else:
            raise MissingRequiredInputError("ciphertext")
    else:
        raise TypeError(f"Invalid package type: {type(package)}")

    if format_name != ENCRYPTION_FORMAT_V1:
        raise UnsupportedFormatOrKeyError(f"Unsupported encryption format version: '{format_name}'")

    if len(nonce) != 12:
        raise CiphertextAuthFailedError(f"Invalid nonce length: expected 12 bytes, got {len(nonce)}")
    if len(tag) != 16:
        raise CiphertextAuthFailedError(f"Invalid GCM tag length: expected 16 bytes, got {len(tag)}")

    # Step 2: Unwrap DEK
    dek = key_provider.unwrap_key(wrapped_key, key_name)
    if len(dek) != 32:
        raise UnsupportedFormatOrKeyError("Unwrapped DEK is not 256 bits")

    try:
        # Step 3: Reconstruct canonical AAD
        aad = build_canonical_aad(
            case_id=case_id,
            document_id=document_id,
            version_id=version_id,
            digest=expected_digest,
            format_name=format_name,
        )

        # Step 4: Decrypt & authenticate tag
        aesgcm = AESGCM(dek)
        # Combine cipher + tag for cryptography AESGCM
        payload_with_tag = cipher + tag
        try:
            plaintext = aesgcm.decrypt(nonce, payload_with_tag, aad)
        except InvalidTag as e:
            raise CiphertextAuthFailedError(
                "AES-256-GCM authentication failed (ciphertext, tag, or AAD modified)"
            ) from e

        # Step 5: Plaintext SHA-256 digest verification
        recomputed_digest = compute_sha256_bytes(plaintext)
        if recomputed_digest.lower() != expected_digest.lower():
            raise PlaintextDigestMismatchError(
                expected=expected_digest,
                actual=recomputed_digest,
            )

        # Step 6: Return verified plaintext
        return plaintext
    finally:
        del dek
