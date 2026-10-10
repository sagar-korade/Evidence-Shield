"""Original-byte hashing module for EvidenceShield AI.

Computes exact SHA-256 digests over original file bytes and buffers without modification.
"""

import hashlib
from pathlib import Path
from typing import BinaryIO, Union


def compute_sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 digest of byte array returning lowercase hex string."""
    return hashlib.sha256(data).hexdigest()


def compute_sha256_raw(data: bytes) -> bytes:
    """Compute SHA-256 digest of byte array returning raw 32-byte digest."""
    return hashlib.sha256(data).digest()


def compute_sha256_stream(stream: BinaryIO, chunk_size: int = 65536) -> str:
    """Compute SHA-256 digest of a binary stream using buffered chunks."""
    hasher = hashlib.sha256()
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)
    return hasher.hexdigest()


def compute_sha256_file(file_path: Union[str, Path], chunk_size: int = 65536) -> str:
    """Compute SHA-256 digest of a file on disk."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")
    with open(path, "rb") as f:
        return compute_sha256_stream(f, chunk_size=chunk_size)


def verify_bytes_digest(data: bytes, expected_digest: str) -> bool:
    """Verify that bytes match expected hex SHA-256 digest in constant time."""
    actual = compute_sha256_bytes(data)
    import hmac
    return hmac.compare_digest(actual.lower(), expected_digest.lower())
