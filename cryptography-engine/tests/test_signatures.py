import pytest

from evidenceshield_crypto.errors import (
    InvalidSignatureError,
    MissingRequiredInputError,
    UnsupportedFormatOrKeyError,
)
from evidenceshield_crypto.key_provider import LocalSimulatedVaultProvider
from evidenceshield_crypto.signatures import (
    TrustedKeyStore,
    sign_canonical_payload,
    verify_canonical_payload,
)


def test_canonical_ed25519_sign_and_verify():
    kp = LocalSimulatedVaultProvider()
    key_name = "test-ed25519"
    pub_bytes = kp.get_public_key_bytes(key_name)
    key_id = "vault://transit/keys/test-ed25519-v1"

    store = TrustedKeyStore()
    store.add_key(key_id, pub_bytes)

    payload = {
        "case_id": "CASE-2026-09",
        "document_id": "DOC-771",
        "version_id": "v1",
        "state": "SEALED",
    }

    signed = sign_canonical_payload(payload, kp, key_name, key_id=key_id)
    assert "signature" in signed
    assert signed["key_id"] == key_id

    # Verification must succeed
    assert verify_canonical_payload(payload, signed["signature"], key_id, store)


def test_corrupted_signature_fails_closed():
    kp = LocalSimulatedVaultProvider()
    key_name = "test-key"
    pub_bytes = kp.get_public_key_bytes(key_name)
    key_id = "vault://test-key"

    store = TrustedKeyStore()
    store.add_key(key_id, pub_bytes)

    payload = {"case_id": "CASE-101", "state": "INGESTED"}
    signed = sign_canonical_payload(payload, kp, key_name, key_id=key_id)

    # Corrupt base64 signature
    corrupt_sig = "A" * len(signed["signature"])
    with pytest.raises(InvalidSignatureError):
        verify_canonical_payload(payload, corrupt_sig, key_id, store)


def test_untrusted_key_fails():
    kp = LocalSimulatedVaultProvider()
    key_name = "test-key"
    store = TrustedKeyStore()  # empty store

    payload = {"case_id": "CASE-101"}
    signed = sign_canonical_payload(payload, kp, key_name, key_id="unknown-key")

    with pytest.raises(UnsupportedFormatOrKeyError):
        verify_canonical_payload(payload, signed["signature"], "unknown-key", store)
