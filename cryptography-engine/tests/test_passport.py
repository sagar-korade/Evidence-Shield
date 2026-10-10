import json
import pytest

from evidenceshield_crypto.anchor import SimulatedAnchorClient
from evidenceshield_crypto.encryption import encrypt_evidence_bytes
from evidenceshield_crypto.key_provider import LocalSimulatedVaultProvider
from evidenceshield_crypto.merkle import RFC9162MerkleTree
from evidenceshield_crypto.passport import (
    create_checkpoint,
    verify_evidence_passport,
)
from evidenceshield_crypto.schemas import (
    AnchorReceiptSchema,
    EncryptionMetadataSchema,
    EvidencePassportSchema,
    InclusionProofSchema,
)
from evidenceshield_crypto.signatures import TrustedKeyStore


def test_full_passport_lifecycle():
    kp = LocalSimulatedVaultProvider()
    key_name = "court-signing-key"
    pub_bytes = kp.get_public_key_bytes(key_name)
    key_id = "vault://transit/keys/court-v1"

    store = TrustedKeyStore()
    store.add_key(key_id, pub_bytes)

    anchor_client = SimulatedAnchorClient()

    # 1. Ingest evidence document
    original_doc = b"FORENSIC BALLISTICS REPORT #2026-0091: Confirmed propellant residue match"
    pkg = encrypt_evidence_bytes(
        original_bytes=original_doc,
        case_id="CAS-2026-99",
        document_id="DOC-88",
        version_id="v1",
        key_provider=kp,
        key_name=key_name,
        state="INGESTED",
    )

    # 2. Append to Merkle tree
    # In EvidenceShield, leaf is domain-separated hash of original doc digest
    doc_digest_bytes = bytes.fromhex(pkg.digest)
    tree = RFC9162MerkleTree([doc_digest_bytes])
    root = tree.get_root_hash()
    proof = tree.get_inclusion_proof(0)

    # 3. Anchor Merkle root on-chain
    receipt = anchor_client.anchor_root(tree_size=1, merkle_root_hex=root.hex())

    # 4. Create and sign checkpoint
    checkpoint = create_checkpoint(
        tree_size=1,
        merkle_root=root.hex(),
        key_provider=kp,
        key_name=key_name,
        key_id=key_id,
    )

    # 5. Assemble Evidence Passport
    passport = EvidencePassportSchema(
        passport_version="evidenceshield-passport-v1",
        case_id=pkg.case_id,
        document_id=pkg.document_id,
        version_id=pkg.version_id,
        state=pkg.state,
        digest=pkg.digest,
        encryption=EncryptionMetadataSchema(
            format=pkg.format,
            key_name=pkg.key_name,
            wrapped_key=pkg.wrapped_key,
            nonce_hex=pkg.nonce.hex(),
            tag_hex=pkg.tag.hex(),
            ciphertext_len=len(pkg.ciphertext),
        ),
        inclusion_proof=InclusionProofSchema(
            leaf_index=0,
            tree_size=1,
            leaf_hash=tree.leaf_hashes[0].hex(),
            proof=[p.hex() for p in proof],
        ),
        checkpoint=checkpoint,
        anchor_receipt=AnchorReceiptSchema(
            tree_size=receipt.tree_size,
            merkle_root=receipt.merkle_root_hex,
            tx_hash=receipt.tx_hash,
            block_number=receipt.block_number,
            contract_address=receipt.contract_address,
            timestamp=receipt.timestamp,
            confirmed=receipt.confirmed,
        ),
    )

    # 6. Verify Passport
    res = verify_evidence_passport(
        passport_data=passport,
        trusted_keys=store,
        anchor_client=anchor_client,
        require_anchor=True,
    )

    assert res.is_valid
    assert res.case_id == "CAS-2026-99"
    assert res.signature_verified
    assert res.merkle_inclusion_verified
    assert res.anchor_verified
