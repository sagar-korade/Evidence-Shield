"""Canonical Pydantic Schemas for EvidenceShield AI Cryptography & Proofs.

Preserves core judicial identity invariants:
- case_id
- document_id
- version_id
- state
- digest
"""

from typing import Any, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class CanonicalBaseModel(BaseModel):
    """Base model configured for canonical JSON serialization."""
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class CheckpointSchema(CanonicalBaseModel):
    """Checkpoint attestation representing a signed cumulative Merkle root."""
    tree_size: int = Field(..., ge=1, description="Cumulative number of leaves")
    merkle_root: str = Field(..., description="SHA-256 root hash in hex")
    timestamp: int = Field(..., description="Epoch seconds of checkpoint signing")
    key_id: str = Field(..., description="Versioned public key identifier")
    signature: str = Field(..., description="Base64-encoded Ed25519 signature")


class InclusionProofSchema(CanonicalBaseModel):
    """RFC 9162 Merkle inclusion proof for a single leaf."""
    leaf_index: int = Field(..., ge=0, description="0-indexed leaf position")
    tree_size: int = Field(..., ge=1, description="Tree size at time of proof generation")
    leaf_hash: str = Field(..., description="RFC 9162 domain-separated leaf hash in hex")
    proof: List[str] = Field(..., description="Audit path sibling hashes in hex")


class AnchorReceiptSchema(CanonicalBaseModel):
    """On-chain blockchain anchor receipt."""
    tree_size: int = Field(..., ge=1)
    merkle_root: str = Field(..., description="Anchored root in hex")
    tx_hash: str = Field(..., description="Transaction hash on EVM/Anvil")
    block_number: int = Field(..., ge=0)
    contract_address: str = Field(...)
    timestamp: int = Field(...)
    confirmed: bool = Field(default=True)


class EncryptionMetadataSchema(CanonicalBaseModel):
    """AES-256-GCM envelope and Vault Transit wrapping metadata."""
    format: str = Field(default="evidenceshield-v1-aes256gcm")
    key_name: str = Field(...)
    wrapped_key: str = Field(...)
    nonce_hex: str = Field(...)
    tag_hex: str = Field(...)
    ciphertext_len: Optional[int] = Field(default=None)


class EvidencePassportSchema(CanonicalBaseModel):
    """Complete Evidence Passport binding document metadata, encryption, Merkle proof, and anchor."""
    passport_version: str = Field(default="evidenceshield-passport-v1")
    case_id: str = Field(...)
    document_id: str = Field(...)
    version_id: str = Field(...)
    state: str = Field(...)
    digest: str = Field(..., description="SHA-256 hex digest of exact original bytes")
    encryption: EncryptionMetadataSchema = Field(...)
    inclusion_proof: InclusionProofSchema = Field(...)
    checkpoint: CheckpointSchema = Field(...)
    anchor_receipt: Optional[AnchorReceiptSchema] = Field(default=None)
    metadata: Optional[dict[str, Any]] = Field(default=None)
