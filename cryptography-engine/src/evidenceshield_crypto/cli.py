"""Standalone CLI Verifier for EvidenceShield AI.

Provides independent offline and online verification of evidence files,
Evidence Passports, and Merkle proofs for judicial defense, prosecution,
and forensic audit.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from evidenceshield_crypto.canonicalization import canonicalize_json_str
from evidenceshield_crypto.errors import EvidenceCryptoError
from evidenceshield_crypto.hashing import compute_sha256_file
from evidenceshield_crypto.merkle import verify_inclusion_proof
from evidenceshield_crypto.passport import verify_evidence_passport
from evidenceshield_crypto.signatures import TrustedKeyStore


def load_trusted_keys_from_file(keys_path: Path) -> TrustedKeyStore:
    """Load JSON mapping key_id -> hex-encoded Ed25519 public key."""
    if not keys_path.exists():
        raise FileNotFoundError(f"Trusted keys file not found: {keys_path}")
    with open(keys_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    store = TrustedKeyStore()
    for kid, hex_key in data.items():
        store.add_key(kid, bytes.fromhex(hex_key))
    return store


def cmd_verify_file(args: argparse.Namespace) -> int:
    """Compute and verify SHA-256 of file against expected digest."""
    path = Path(args.file)
    actual = compute_sha256_file(path)
    if args.expected_digest:
        matched = (actual.lower() == args.expected_digest.lower())
        result = {
            "file": str(path),
            "actual_digest": actual,
            "expected_digest": args.expected_digest.lower(),
            "matches": matched,
        }
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            status = "PASS" if matched else "FAIL"
            print(f"[{status}] File digest verification: {path.name}")
            print(f"  Computed: {actual}")
            print(f"  Expected: {args.expected_digest}")
        return 0 if matched else 1
    else:
        if args.json:
            print(json.dumps({"file": str(path), "sha256": actual}, indent=2))
        else:
            print(f"SHA-256 ({path.name}): {actual}")
        return 0


def cmd_verify_passport(args: argparse.Namespace) -> int:
    """Verify an Evidence Passport JSON file."""
    passport_path = Path(args.passport)
    if not passport_path.exists():
        print(f"Error: Passport file not found: {passport_path}", file=sys.stderr)
        return 2

    keys_path = Path(args.trusted_keys)
    try:
        trusted_keys = load_trusted_keys_from_file(keys_path)
    except Exception as e:
        print(f"Error loading trusted keys: {e}", file=sys.stderr)
        return 2

    with open(passport_path, "r", encoding="utf-8") as f:
        passport_data = json.load(f)

    try:
        res = verify_evidence_passport(
            passport_data=passport_data,
            trusted_keys=trusted_keys,
            require_anchor=args.require_anchor,
        )

        # Optional file check
        file_check = None
        if args.file:
            actual_digest = compute_sha256_file(args.file)
            file_match = (actual_digest.lower() == res.digest.lower())
            file_check = {
                "file": args.file,
                "file_digest": actual_digest,
                "passport_digest": res.digest,
                "matches": file_match,
            }
            if not file_match:
                res.is_valid = False

        output = {
            "status": "VALID" if res.is_valid else "INVALID",
            "case_id": res.case_id,
            "document_id": res.document_id,
            "version_id": res.version_id,
            "digest": res.digest,
            "signature_verified": res.signature_verified,
            "merkle_inclusion_verified": res.merkle_inclusion_verified,
            "anchor_verified": res.anchor_verified,
            "details": res.details,
            "file_check": file_check,
        }

        if args.json:
            print(json.dumps(output, indent=2))
        else:
            print(f"==================================================")
            print(f" EvidenceShield Passport Verification: {output['status']}")
            print(f"==================================================")
            print(f" Case ID:           {res.case_id}")
            print(f" Document ID:       {res.document_id}")
            print(f" Version ID:        {res.version_id}")
            print(f" Digest (SHA-256):  {res.digest}")
            print(f" Signature:         {'VALID' if res.signature_verified else 'INVALID'}")
            print(f" Merkle Proof:      {'VALID' if res.merkle_inclusion_verified else 'INVALID'}")
            print(f" Blockchain Anchor: {'CONFIRMED' if res.anchor_verified else 'UNCONFIRMED'}")
            if file_check:
                fc_stat = "MATCH" if file_check["matches"] else "MISMATCH"
                print(f" Evidence File:     [{fc_stat}] {file_check['file']}")
            print(f"==================================================")

        return 0 if res.is_valid else 1

    except EvidenceCryptoError as e:
        err_out = e.to_dict()
        if args.json:
            print(json.dumps({"status": "FAILED", "error": err_out}, indent=2))
        else:
            print(f"[VERIFICATION FAILED: {err_out['error_code']}] {err_out['message']}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error during passport verification: {e}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evidenceshield-verify",
        description="EvidenceShield AI Cryptographic Verification CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # verify-file
    p_file = subparsers.add_parser("verify-file", help="Compute or verify file SHA-256 hash")
    p_file.add_argument("file", help="Path to evidence file")
    p_file.add_argument("--expected-digest", "-e", help="Expected SHA-256 hex digest")
    p_file.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # verify-passport
    p_pass = subparsers.add_parser("verify-passport", help="Verify Evidence Passport integrity")
    p_pass.add_argument("passport", help="Path to evidence passport JSON file")
    p_pass.add_argument("--trusted-keys", "-k", required=True, help="Path to trusted public keys JSON")
    p_pass.add_argument("--file", "-f", help="Path to original evidence file (optional file-match check)")
    p_pass.add_argument("--require-anchor", action="store_true", help="Enforce on-chain anchor requirement")
    p_pass.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "verify-file":
        code = cmd_verify_file(args)
    elif args.command == "verify-passport":
        code = cmd_verify_passport(args)
    else:
        parser.print_help()
        code = 2
    sys.exit(code)


if __name__ == "__main__":
    main()
