"""Controlled Corruption Fixture Suite.

Demonstrates that the cryptographic verification engine fails closed
under all attack and corruption vectors, raising the exact approved
machine-readable error codes.
"""

import json
from pathlib import Path
import pytest

from evidenceshield_crypto.anchor import AnchorReceipt, SimulatedAnchorClient
from evidenceshield_crypto.encryption import (
    decrypt_and_verify_evidence,
    encrypt_evidence_bytes,
)
from evidenceshield_crypto.errors import (
    AnchorVerificationFailedError,
    CiphertextAuthFailedError,
    ErrorCode,
    InvalidConsistencyProofError,
    InvalidInclusionProofError,
    InvalidSignatureError,
    MissingRequiredInputError,
    PendingAnchorError,
    PlaintextDigestMismatchError,
    UnsupportedFormatOrKeyError,
)
from evidenceshield_crypto.key_provider import LocalSimulatedVaultProvider
from evidenceshield_crypto.merkle import (
    RFC9162MerkleTree,
    hash_leaf,
    verify_consistency_proof,
    verify_inclusion_proof,
)
from evidenceshield_crypto.passport import (
    create_checkpoint,
    verify_evidence_passport,
)
from evidenceshield_crypto.schemas import (
    AnchorReceiptSchema,
    EvidencePassportSchema,
    InclusionProofSchema,
)
from evidenceshield_crypto.signatures import (
    TrustedKeyStore,
    verify_canonical_payload,
)


@pytest.fixture
def test_setup():
    kp = LocalSimulatedVaultProvider()
    key_name = "judge-signing-key"
    pub_bytes = kp.get_public_key_bytes(key_name)
    key_id = "vault://transit/keys/judge-signing-v1"

    store = TrustedKeyStore()
    store.add_key(key_id, pub_bytes)

    anchor_client = SimulatedAnchorClient()

    return {
        "kp": kp,
        "key_name": key_name,
        "key_id": key_id,
        "pub_bytes": pub_bytes,
        "store": store,
        "anchor_client": anchor_client,
    }


def test_corruption_1_ciphertext_bitflip(test_setup):
    """Vector 1: Modifying 1 bit in ciphertext fails GCM authentication."""
    kp = test_setup["kp"]
    content = b"Original Police First Information Report (FIR) No. 402/2026"
    pkg = encrypt_evidence_bytes(content, "CAS-2026-A", "DOC-402", "v1", kp, "transit-key")

    corrupted = bytearray(pkg.ciphertext)
    corrupted[0] ^= 0x01  # Flip single bit

    with pytest.raises(CiphertextAuthFailedError) as exc_info:
        decrypt_and_verify_evidence(pkg, bytes(corrupted), kp)
    assert exc_info.value.code == ErrorCode.CIPHERTEXT_AUTH_FAILED


def test_corruption_2_altered_aad(test_setup):
    """Vector 2: Swapping case_id in AAD fails GCM authentication."""
    kp = test_setup["kp"]
    content = b"Confidential Witness Testimony"
    pkg = encrypt_evidence_bytes(content, "CAS-2026-A", "DOC-402", "v1", kp, "transit-key")

    tampered_meta = pkg.to_metadata_dict()
    tampered_meta["case_id"] = "CAS-2026-ATTACKER"
    tampered_meta["ciphertext"] = pkg.ciphertext
    tampered_meta["nonce"] = pkg.nonce
    tampered_meta["tag"] = pkg.tag

    with pytest.raises(CiphertextAuthFailedError) as exc_info:
        decrypt_and_verify_evidence(tampered_meta, None, kp)
    assert exc_info.value.code == ErrorCode.CIPHERTEXT_AUTH_FAILED


def test_corruption_3_invalid_signature(test_setup):
    """Vector 3: Corrupting digital signature fails signature verification."""
    store = test_setup["store"]
    key_id = test_setup["key_id"]
    payload = {"case_id": "CAS-2026-A", "state": "SEALED"}

    # Signature with tampered base64
    corrupt_sig = "dGFtcGVyZWQtc2lnbmF0dXJlLWJ5dGVzLWluLXRlc3QtZml4dHVyZS0xMjM0NTY3ODkwMTI="

    with pytest.raises(InvalidSignatureError) as exc_info:
        verify_canonical_payload(payload, corrupt_sig, key_id, store)
    assert exc_info.value.code == ErrorCode.INVALID_SIGNATURE


def test_corruption_4_invalid_inclusion_proof(test_setup):
    """Vector 4: Tampered sibling in Merkle path fails inclusion proof."""
    tree = RFC9162MerkleTree([b"evidence-1", b"evidence-2", b"evidence-3"])
    root = tree.get_root_hash()
    proof = tree.get_inclusion_proof(1)

    # Corrupt one sibling hash
    corrupt_proof = list(proof)
    corrupt_proof[0] = b"\xff" * 32

    leaf_h = tree.leaf_hashes[1]
    with pytest.raises(InvalidInclusionProofError) as exc_info:
        verify_inclusion_proof(leaf_h, 1, 3, corrupt_proof, root)
    assert exc_info.value.code == ErrorCode.INVALID_INCLUSION_PROOF


def test_corruption_5_invalid_consistency_proof(test_setup):
    """Vector 5: Tampered consistency proof node fails verification."""
    tree = RFC9162MerkleTree([b"r1", b"r2", b"r3", b"r4"])
    r1 = tree.get_root_hash(2)
    r2 = tree.get_root_hash(4)
    proof = tree.get_consistency_proof(2, 4)

    corrupt_proof = [b"\xaa" * 32 for _ in proof]
    with pytest.raises(InvalidConsistencyProofError) as exc_info:
        verify_consistency_proof(2, 4, r1, r2, corrupt_proof)
    assert exc_info.value.code == ErrorCode.INVALID_CONSISTENCY_PROOF


def test_corruption_6_unsupported_key(test_setup):
    """Vector 6: Unknown signing key identifier fails closed."""
    store = test_setup["store"]
    payload = {"case_id": "CAS-1"}
    valid_sig = "A" * 88

    with pytest.raises(UnsupportedFormatOrKeyError) as exc_info:
        verify_canonical_payload(payload, valid_sig, "vault://unknown/key", store)
    assert exc_info.value.code == ErrorCode.UNSUPPORTED_FORMAT_OR_KEY


def test_corruption_7_pending_anchor(test_setup):
    """Vector 7: Unmined/pending anchor transaction raises PENDING_ANCHOR."""
    anchor_client = test_setup["anchor_client"]
    receipt = AnchorReceipt(
        tree_size=10,
        merkle_root_hex="a" * 64,
        tx_hash="0xpending123",
        block_number=101,
        contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
        timestamp=1000,
        confirmed=False,
    )
    anchor_client.set_pending("0xpending123", receipt)

    with pytest.raises(PendingAnchorError) as exc_info:
        anchor_client.verify_receipt(receipt, "a" * 64)
    assert exc_info.value.code == ErrorCode.PENDING_ANCHOR


def test_corruption_8_anchor_verification_failed(test_setup):
    """Vector 8: On-chain root mismatch raises ANCHOR_VERIFICATION_FAILED."""
    anchor_client = test_setup["anchor_client"]
    # Commit root A
    receipt = anchor_client.anchor_root(5, "1" * 64)

    # Try to verify against different root B
    with pytest.raises(AnchorVerificationFailedError) as exc_info:
        anchor_client.verify_receipt(receipt, "2" * 64)
    assert exc_info.value.code == ErrorCode.ANCHOR_VERIFICATION_FAILED
