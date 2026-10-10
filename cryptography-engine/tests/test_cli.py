import json
import subprocess
import sys
from pathlib import Path
import pytest

from evidenceshield_crypto.encryption import encrypt_evidence_bytes
from evidenceshield_crypto.key_provider import LocalSimulatedVaultProvider
from evidenceshield_crypto.merkle import RFC9162MerkleTree
from evidenceshield_crypto.passport import create_checkpoint
from evidenceshield_crypto.schemas import (
    EncryptionMetadataSchema,
    EvidencePassportSchema,
    InclusionProofSchema,
)


def test_cli_file_verification(tmp_path):
    test_file = tmp_path / "evidence_doc.txt"
    test_file.write_bytes(b"Confidential forensic transcript")

    # Run cli verify-file
    cmd = [
        sys.executable,
        "-m",
        "evidenceshield_crypto.cli",
        "verify-file",
        str(test_file),
        "--json",
    ]
    res = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parent.parent / "src"),
    )
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert "sha256" in data


def test_cli_passport_verification_pass_and_fail(tmp_path):
    kp = LocalSimulatedVaultProvider()
    key_name = "court-key"
    pub_bytes = kp.get_public_key_bytes(key_name)
    key_id = "vault://transit/keys/court-v1"

    keys_file = tmp_path / "trusted_keys.json"
    keys_file.write_text(json.dumps({key_id: pub_bytes.hex()}), encoding="utf-8")

    evidence_bytes = b"Police evidence item #4092"
    evidence_file = tmp_path / "evidence_item.bin"
    evidence_file.write_bytes(evidence_bytes)

    pkg = encrypt_evidence_bytes(
        evidence_bytes,
        "CAS-101",
        "DOC-99",
        "v1",
        kp,
        key_name,
    )

    doc_digest = bytes.fromhex(pkg.digest)
    tree = RFC9162MerkleTree([doc_digest])
    root = tree.get_root_hash()
    proof = tree.get_inclusion_proof(0)

    checkpoint = create_checkpoint(1, root.hex(), kp, key_name, key_id=key_id)

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
        ),
        inclusion_proof=InclusionProofSchema(
            leaf_index=0,
            tree_size=1,
            leaf_hash=tree.leaf_hashes[0].hex(),
            proof=[p.hex() for p in proof],
        ),
        checkpoint=checkpoint,
    )

    passport_file = tmp_path / "passport.json"
    passport_file.write_text(passport.model_dump_json(indent=2), encoding="utf-8")

    # Run CLI verify-passport with original evidence file check
    cmd = [
        sys.executable,
        "-m",
        "evidenceshield_crypto.cli",
        "verify-passport",
        str(passport_file),
        "-k",
        str(keys_file),
        "-f",
        str(evidence_file),
        "--json",
    ]
    res = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parent.parent / "src"),
    )
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["status"] == "VALID"
    assert data["file_check"]["matches"] is True

    # Now tamper with original evidence file to test file mismatch
    evidence_file.write_bytes(b"TAMPERED FILE CONTENT")
    res_tampered = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parent.parent / "src"),
    )
    assert res_tampered.returncode == 1
