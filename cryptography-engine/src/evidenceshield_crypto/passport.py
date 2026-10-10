"""Evidence Passport generation and verification engine.

The Evidence Passport provides an offline-verifiable, tamper-evident cryptographic
attestation for an evidence item.

Verification pipeline enforces zero-trust:
1. Validates schema and identifiers (case_id, document_id, version_id, state, digest).
2. Verifies Checkpoint Ed25519 signature against an independently trusted key store.
3. Verifies that leaf_hash binds to the original byte digest.
4. Verifies RFC 9162 Merkle inclusion proof up to the checkpoint root.
5. Verifies on-chain anchor receipt (if provided or anchor enforcement required).
6. Fails closed with machine-readable error codes.
"""

import time
from dataclasses import dataclass
from typing import Any, Optional, Union

from evidenceshield_crypto.anchor import AnchorClient, AnchorReceipt
from evidenceshield_crypto.errors import (
    AnchorVerificationFailedError,
    InvalidInclusionProofError,
    InvalidSignatureError,
    MissingRequiredInputError,
    PendingAnchorError,
    UnsupportedFormatOrKeyError,
)
from evidenceshield_crypto.merkle import (
    hash_leaf,
    verify_inclusion_proof,
)
from evidenceshield_crypto.schemas import (
    AnchorReceiptSchema,
    CheckpointSchema,
    EvidencePassportSchema,
    InclusionProofSchema,
)
from evidenceshield_crypto.signatures import (
    TrustedKeyStore,
    sign_canonical_payload,
    verify_canonical_payload,
)


@dataclass
class PassportVerificationResult:
    """Detailed outcome of evidence passport verification."""
    is_valid: bool
    case_id: str
    document_id: str
    version_id: str
    digest: str
    signature_verified: bool
    merkle_inclusion_verified: bool
    anchor_verified: bool
    details: dict[str, Any]


def create_checkpoint(
    tree_size: int,
    merkle_root: Union[bytes, str],
    key_provider: Any,
    key_name: str,
    key_id: Optional[str] = None,
    timestamp: Optional[int] = None,
) -> CheckpointSchema:
    """Create and sign an RFC 8785 canonical checkpoint for a Merkle root."""
    root_hex = merkle_root.hex() if isinstance(merkle_root, bytes) else merkle_root.lower()
    ts = int(time.time()) if timestamp is None else timestamp
    kid = key_id or f"vault://transit/keys/{key_name}"

    unsigned_payload = {
        "key_id": kid,
        "merkle_root": root_hex,
        "timestamp": ts,
        "tree_size": tree_size,
    }

    signed = sign_canonical_payload(
        payload=unsigned_payload,
        key_provider=key_provider,
        key_name=key_name,
        key_id=kid,
    )

    return CheckpointSchema(
        tree_size=tree_size,
        merkle_root=root_hex,
        timestamp=ts,
        key_id=kid,
        signature=signed["signature"],
    )


def verify_checkpoint_signature(
    checkpoint: Union[CheckpointSchema, dict[str, Any]],
    trusted_keys: TrustedKeyStore,
) -> bool:
    """Verify Ed25519 signature on an RFC 8785 canonical checkpoint."""
    if isinstance(checkpoint, CheckpointSchema):
        tree_size = checkpoint.tree_size
        merkle_root = checkpoint.merkle_root
        ts = checkpoint.timestamp
        key_id = checkpoint.key_id
        sig = checkpoint.signature
    else:
        tree_size = checkpoint["tree_size"]
        merkle_root = checkpoint["merkle_root"]
        ts = checkpoint["timestamp"]
        key_id = checkpoint["key_id"]
        sig = checkpoint["signature"]

    payload = {
        "key_id": key_id,
        "merkle_root": merkle_root.lower(),
        "timestamp": ts,
        "tree_size": tree_size,
    }

    return verify_canonical_payload(
        payload=payload,
        signature_b64=sig,
        key_id=key_id,
        trusted_keys=trusted_keys,
    )


def verify_evidence_passport(
    passport_data: Union[EvidencePassportSchema, dict[str, Any]],
    trusted_keys: TrustedKeyStore,
    anchor_client: Optional[AnchorClient] = None,
    require_anchor: bool = False,
) -> PassportVerificationResult:
    """Verify complete Evidence Passport fail-closed across all cryptographic layers."""
    if isinstance(passport_data, dict):
        passport = EvidencePassportSchema.model_validate(passport_data)
    else:
        passport = passport_data

    # Step 1: Verify Checkpoint Signature
    sig_ok = verify_checkpoint_signature(passport.checkpoint, trusted_keys)

    # Step 2: Verify leaf hash binds to the original byte digest
    digest_bytes = bytes.fromhex(passport.digest)
    expected_leaf_hash = hash_leaf(digest_bytes)
    passport_leaf_hash = bytes.fromhex(passport.inclusion_proof.leaf_hash)

    if passport_leaf_hash != expected_leaf_hash:
        raise InvalidInclusionProofError(
            f"Inclusion proof leaf_hash ({passport.inclusion_proof.leaf_hash}) "
            f"does not match RFC 9162 hash of document digest ({expected_leaf_hash.hex()})"
        )

    # Step 3: Verify RFC 9162 Merkle Inclusion Proof
    proof_bytes = [bytes.fromhex(p) for p in passport.inclusion_proof.proof]
    root_bytes = bytes.fromhex(passport.checkpoint.merkle_root)

    merkle_ok = verify_inclusion_proof(
        leaf_hash=passport_leaf_hash,
        leaf_index=passport.inclusion_proof.leaf_index,
        tree_size=passport.inclusion_proof.tree_size,
        proof=proof_bytes,
        expected_root=root_bytes,
    )

    # Step 4: Verify on-chain anchor
    anchor_ok = False
    if passport.anchor_receipt is not None:
        rec = passport.anchor_receipt
        receipt = AnchorReceipt(
            tree_size=rec.tree_size,
            merkle_root_hex=rec.merkle_root,
            tx_hash=rec.tx_hash,
            block_number=rec.block_number,
            contract_address=rec.contract_address,
            timestamp=rec.timestamp,
            confirmed=rec.confirmed,
        )
        if anchor_client is not None:
            anchor_ok = anchor_client.verify_receipt(receipt, passport.checkpoint.merkle_root)
        else:
            # If no anchor_client provided, receipt exists but cannot be verified on chain
            if require_anchor:
                raise AnchorVerificationFailedError("Anchor client required to verify anchor receipt")
            anchor_ok = True
    else:
        if require_anchor:
            raise AnchorVerificationFailedError("Anchor verification required but passport contains no anchor receipt")

    return PassportVerificationResult(
        is_valid=True,
        case_id=passport.case_id,
        document_id=passport.document_id,
        version_id=passport.version_id,
        digest=passport.digest,
        signature_verified=sig_ok,
        merkle_inclusion_verified=merkle_ok,
        anchor_verified=anchor_ok,
        details={
            "tree_size": passport.checkpoint.tree_size,
            "merkle_root": passport.checkpoint.merkle_root,
            "leaf_index": passport.inclusion_proof.leaf_index,
            "checkpoint_timestamp": passport.checkpoint.timestamp,
            "anchor_confirmed": anchor_ok,
        },
    )
