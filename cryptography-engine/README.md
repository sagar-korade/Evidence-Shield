# EvidenceShield AI — Cryptography & Proof Engine

Independently developed zero-trust cryptographic core and verification engine for **EvidenceShield AI**: a Tamper-Evident Zero-Trust Judicial & Forensic Document Management System.

---

## 1. Scope & Security Model

- **Zero-Trust & Fail-Closed**: Any cryptographic mismatch (authentication tag, plaintext hash, digital signature, Merkle proof, or on-chain anchor) terminates execution immediately without exposing decrypted plaintext.
- **Strict Separation of Concerns**: The cryptography engine reports machine-readable cryptographic outcomes; it does **not** mutate database custody records, quarantine tables, or assign user permissions.
- **No Browser-Accessible Decryption/Key APIs**: Decryption and Vault key operations are strictly consumed by internal backend and integrity worker services. Plaintext keys and raw decrypted evidence are never cached or exposed to client browsers.
- **Canonical Invariants**: Preserves the approved domain naming standard:
  `case_id`, `document_id`, `version_id`, `state`, `digest`. (Legacy identifiers `evidence_id`, `item_id`, `case_ref` are forbidden).

---

## 2. Architecture & Modules

```
cryptography-engine/
├── contracts/
│   └── EvidenceAnchor.sol              # Solidity on-chain anchor contract for local Anvil / EVM
├── fixtures/
│   └── corruption_manifest.json        # Controlled corruption test vectors & error definitions
├── src/
│   └── evidenceshield_crypto/
│       ├── __init__.py                 # Clean package API
│       ├── errors.py                   # Standardized machine-readable error codes
│       ├── hashing.py                  # SHA-256 original-byte hashing
│       ├── canonicalization.py         # RFC 8785 JSON Canonicalization Scheme (JCS)
│       ├── key_provider.py             # Dependency-injected Vault Transit & test simulator
│       ├── signatures.py               # Ed25519 canonical digital signatures
│       ├── encryption.py               # AES-256-GCM authenticated encryption/decryption
│       ├── merkle.py                   # RFC 9162 domain-separated cumulative Merkle tree
│       ├── anchor.py                   # Blockchain anchor client & receipt verification
│       ├── schemas.py                  # Canonical Pydantic schemas (Passports, Checkpoints)
│       ├── passport.py                 # End-to-end Evidence Passport verification pipeline
│       └── cli.py                      # Standalone CLI verifier for judicial inspection
└── tests/
    ├── test_hashing.py                 # SHA-256 byte/stream tests
    ├── test_canonicalization.py        # RFC 8785 JCS test vectors
    ├── test_signatures.py              # Ed25519 signature tests
    ├── test_encryption.py              # AES-256-GCM fresh key/nonce & AAD tests
    ├── test_merkle_rfc9162.py          # RFC 9162 inclusion/consistency proof tests
    ├── test_corruption_fixtures.py     # 8 controlled corruption fail-closed tests
    ├── test_passport.py                # Full passport verification lifecycle
    └── test_cli.py                     # CLI verification test suite
```

---

## 3. Cryptographic Specifications

### Original-Byte Hashing
- Computes SHA-256 over exact original bytes without normalization, transcoding, or byte stripping.
- Streaming support for large files to bound memory consumption.

### AES-256-GCM Authenticated Encryption
- **DEK**: Fresh 256-bit cryptographically secure key generated per immutable evidence version (`os.urandom(32)`).
- **Nonce**: Unique 96-bit nonce per encryption (`os.urandom(12)`).
- **AAD (Additional Authenticated Data)**: Deterministic RFC 8785 canonical JSON binding:
  `{"case_id":..., "document_id":..., "format":"evidenceshield-v1-aes256gcm", "original_digest":..., "version_id":...}`
- **Key Wrapping**: DEK wrapped via HashiCorp Vault Transit (`vault:v1:...`).
- Plaintext keys are wiped from references immediately after encryption/decryption.

### RFC 8785 Canonical JSON & Ed25519 Signatures
- Strict UTF-16 code unit property key sorting.
- Whitespace stripping.
- Strict numeric handling (rejects `NaN` and `Infinity`).
- Ed25519 64-byte signatures over canonical bytes.
- Verification keys resolved exclusively from `TrustedKeyStore`; self-asserted keys in untrusted payloads are rejected.

### RFC 9162 Cumulative Merkle Log
- **Leaf Hash**: `SHA-256(0x00 || leaf_data)`
- **Internal Node Hash**: `SHA-256(0x01 || left_hash || right_hash)`
- **Split Rule**: `k = 2^floor(log2(n - 1))` (largest power of 2 less than `n`).
- **No Leaf Duplication**: Odd trees follow standard split rules without duplicating odd leaves.
- **Inclusion Proofs**: Audit paths proving leaf membership in root.
- **Consistency Proofs**: Verification that tree size $m$ is an immutable prefix of tree size $n$ ($m \le n$).

### On-Chain Solidity Anchor (`EvidenceAnchor.sol`)
- Deployed to persistent local Anvil (`http://127.0.0.1:8545`).
- Strictly monotonic tree size enforcement (`treeSize > latestTreeSize`).
- Emits `MerkleRootAnchored(treeSize, merkleRoot, timestamp, blockNumber, anchorer)`.

---

## 4. Machine-Readable Error Catalog

| Error Code | Exception Class | Trigger Condition |
| :--- | :--- | :--- |
| `CIPHERTEXT_AUTH_FAILED` | `CiphertextAuthFailedError` | AES-GCM tag verification failure or altered AAD. |
| `PLAINTEXT_DIGEST_MISMATCH` | `PlaintextDigestMismatchError` | Plaintext SHA-256 does not match immutable version digest. |
| `INVALID_SIGNATURE` | `InvalidSignatureError` | Checkpoint or event Ed25519 digital signature fails. |
| `INVALID_INCLUSION_PROOF` | `InvalidInclusionProofError` | Merkle audit path does not evaluate to checkpoint root. |
| `INVALID_CONSISTENCY_PROOF` | `InvalidConsistencyProofError` | Tree state consistency check fails between sizes $m$ and $n$. |
| `UNSUPPORTED_FORMAT_OR_KEY` | `UnsupportedFormatOrKeyError` | Unknown format version or unresolvable key reference. |
| `MISSING_REQUIRED_INPUT` | `MissingRequiredInputError` | Mandatory cryptographic fields missing from payload. |
| `ANCHOR_VERIFICATION_FAILED` | `AnchorVerificationFailedError` | On-chain contract root differs from checkpoint root. |
| `PENDING_ANCHOR` | `PendingAnchorError` | Anchor transaction is pending block confirmation. |

---

## 5. Usage & Verification CLI

### Python API Integration
```python
from evidenceshield_crypto import (
    encrypt_evidence_bytes,
    decrypt_and_verify_evidence,
    RFC9162MerkleTree,
    create_checkpoint,
    verify_evidence_passport,
    LocalSimulatedVaultProvider,
    TrustedKeyStore,
)

# 1. Encrypt original bytes
kp = LocalSimulatedVaultProvider()
pkg = encrypt_evidence_bytes(
    original_bytes=b"Forensic autopsy report...",
    case_id="CAS-2026-001",
    document_id="DOC-902",
    version_id="v1",
    key_provider=kp,
    key_name="transit-key-1",
)

# 2. Decrypt & verify (fails closed if tampered)
plaintext = decrypt_and_verify_evidence(pkg, None, kp)
```

### Standalone CLI Verifier
```bash
# Verify original file SHA-256
python -m evidenceshield_crypto.cli verify-file /path/to/evidence.pdf -e <expected-sha256>

# Verify Evidence Passport against trusted keys and original evidence file
python -m evidenceshield_crypto.cli verify-passport passport.json -k trusted_keys.json -f /path/to/evidence.pdf --json
```

---

## 6. Running Tests
```bash
pytest -v
```
All 34 test cases covering unit primitives, RFC 8785 vectors, RFC 9162 tree semantics, and controlled corruption fail-closed assertions pass cleanly.
