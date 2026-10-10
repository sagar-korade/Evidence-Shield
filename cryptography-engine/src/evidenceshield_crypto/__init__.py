"""EvidenceShield AI Cryptography & Proof Engine.

Independently developed zero-trust judicial cryptographic package:
- SHA-256 original-byte hashing
- AES-256-GCM authenticated encryption and fail-closed decryption
- Vault Transit key wrapping and Ed25519 canonical signing
- RFC 8785 JSON canonicalization (JCS)
- RFC 9162 cumulative Merkle trees, inclusion and consistency proofs
- Evidence Passport generation and offline/online verification
- Blockchain anchor receipts and smart contracts
"""

from evidenceshield_crypto.errors import (
    AnchorVerificationFailedError,
    CiphertextAuthFailedError,
    ErrorCode,
    EvidenceCryptoError,
    InvalidConsistencyProofError,
    InvalidInclusionProofError,
    InvalidSignatureError,
    MissingRequiredInputError,
    PendingAnchorError,
    PlaintextDigestMismatchError,
    UnsupportedFormatOrKeyError,
)
from evidenceshield_crypto.hashing import (
    compute_sha256_bytes,
    compute_sha256_file,
    compute_sha256_raw,
    compute_sha256_stream,
    verify_bytes_digest,
)
from evidenceshield_crypto.canonicalization import (
    canonicalize_json,
    canonicalize_json_str,
)
from evidenceshield_crypto.key_provider import (
    KeyProvider,
    LocalSimulatedVaultProvider,
    VaultTransitClient,
)
from evidenceshield_crypto.signatures import (
    TrustedKeyStore,
    sign_canonical_payload,
    verify_canonical_payload,
)
from evidenceshield_crypto.encryption import (
    ENCRYPTION_FORMAT_V1,
    EncryptedPackage,
    build_canonical_aad,
    decrypt_and_verify_evidence,
    encrypt_evidence_bytes,
)
from evidenceshield_crypto.merkle import (
    RFC9162MerkleTree,
    hash_children,
    hash_leaf,
    verify_consistency_proof,
    verify_inclusion_proof,
)
from evidenceshield_crypto.anchor import (
    AnchorClient,
    AnchorReceipt,
    SimulatedAnchorClient,
    Web3AnvilAnchorClient,
)
from evidenceshield_crypto.passport import (
    PassportVerificationResult,
    create_checkpoint,
    verify_checkpoint_signature,
    verify_evidence_passport,
)

__all__ = [
    # Errors
    "ErrorCode",
    "EvidenceCryptoError",
    "CiphertextAuthFailedError",
    "PlaintextDigestMismatchError",
    "InvalidSignatureError",
    "InvalidInclusionProofError",
    "InvalidConsistencyProofError",
    "UnsupportedFormatOrKeyError",
    "MissingRequiredInputError",
    "AnchorVerificationFailedError",
    "PendingAnchorError",
    # Hashing
    "compute_sha256_bytes",
    "compute_sha256_raw",
    "compute_sha256_stream",
    "compute_sha256_file",
    "verify_bytes_digest",
    # Canonicalization
    "canonicalize_json",
    "canonicalize_json_str",
    # Key Providers
    "KeyProvider",
    "LocalSimulatedVaultProvider",
    "VaultTransitClient",
    # Signatures
    "TrustedKeyStore",
    "sign_canonical_payload",
    "verify_canonical_payload",
    # Encryption
    "ENCRYPTION_FORMAT_V1",
    "EncryptedPackage",
    "build_canonical_aad",
    "encrypt_evidence_bytes",
    "decrypt_and_verify_evidence",
    # Merkle
    "RFC9162MerkleTree",
    "hash_leaf",
    "hash_children",
    "verify_inclusion_proof",
    "verify_consistency_proof",
    # Anchor
    "AnchorClient",
    "AnchorReceipt",
    "SimulatedAnchorClient",
    "Web3AnvilAnchorClient",
    # Passport
    "PassportVerificationResult",
    "create_checkpoint",
    "verify_checkpoint_signature",
    "verify_evidence_passport",
]
