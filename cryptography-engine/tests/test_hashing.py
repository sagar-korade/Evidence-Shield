import hashlib
import io
import pytest

from evidenceshield_crypto.hashing import (
    compute_sha256_bytes,
    compute_sha256_raw,
    compute_sha256_stream,
    verify_bytes_digest,
)


def test_compute_sha256_bytes_known_vector():
    data = b"EvidenceShield AI Judicial Ingestion"
    expected = hashlib.sha256(data).hexdigest()
    assert compute_sha256_bytes(data) == expected
    assert compute_sha256_raw(data) == hashlib.sha256(data).digest()


def test_compute_sha256_stream_matches_bytes():
    data = b"A" * 100000 + b"B" * 50000
    expected = hashlib.sha256(data).hexdigest()
    stream = io.BytesIO(data)
    actual = compute_sha256_stream(stream, chunk_size=4096)
    assert actual == expected


def test_verify_bytes_digest():
    data = b"forensic-evidence-v1"
    digest = hashlib.sha256(data).hexdigest()
    assert verify_bytes_digest(data, digest)
    assert verify_bytes_digest(data, digest.upper())
    assert not verify_bytes_digest(data, "0" * 64)
