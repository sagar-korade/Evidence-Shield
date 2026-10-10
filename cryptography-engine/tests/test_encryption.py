import pytest

from evidenceshield_crypto.encryption import (
    ENCRYPTION_FORMAT_V1,
    decrypt_and_verify_evidence,
    encrypt_evidence_bytes,
)
from evidenceshield_crypto.errors import (
    CiphertextAuthFailedError,
    MissingRequiredInputError,
    PlaintextDigestMismatchError,
    UnsupportedFormatOrKeyError,
)
from evidenceshield_crypto.key_provider import LocalSimulatedVaultProvider


def test_encryption_fresh_keys_and_nonces():
    kp = LocalSimulatedVaultProvider()
    data = b"Autopsy report forensic bytes"
    pkg1 = encrypt_evidence_bytes(data, "CAS-1", "DOC-1", "v1", kp, "key1")
    pkg2 = encrypt_evidence_bytes(data, "CAS-1", "DOC-1", "v1", kp, "key1")

    # Digests of identical original file must be identical
    assert pkg1.digest == pkg2.digest
    # Fresh nonces and keys mean ciphertexts and nonces must differ
    assert pkg1.nonce != pkg2.nonce
    assert pkg1.ciphertext != pkg2.ciphertext


def test_roundtrip_decryption_and_verification():
    kp = LocalSimulatedVaultProvider()
    original = b"Ballistics report - matching firearm serial 8841-A"
    pkg = encrypt_evidence_bytes(original, "CAS-10", "DOC-20", "v1", kp, "key-transit")

    decrypted = decrypt_and_verify_evidence(pkg, None, kp)
    assert decrypted == original


def test_ciphertext_corruption_fails_authentication():
    kp = LocalSimulatedVaultProvider()
    original = b"Secure digital forensic disk image fragment"
    pkg = encrypt_evidence_bytes(original, "CAS-10", "DOC-20", "v1", kp, "key-transit")

    # Flip one byte in ciphertext
    corrupt_ciphertext = bytearray(pkg.ciphertext)
    corrupt_ciphertext[0] ^= 0x01

    with pytest.raises(CiphertextAuthFailedError):
        decrypt_and_verify_evidence(pkg, bytes(corrupt_ciphertext), kp)


def test_modified_tag_fails_authentication():
    kp = LocalSimulatedVaultProvider()
    original = b"Forensic chain of custody record"
    pkg = encrypt_evidence_bytes(original, "CAS-10", "DOC-20", "v1", kp, "key-transit")

    # Corrupt tag
    corrupt_tag = bytearray(pkg.tag)
    corrupt_tag[-1] ^= 0x55

    dict_pkg = pkg.to_metadata_dict()
    dict_pkg["tag"] = bytes(corrupt_tag)
    dict_pkg["ciphertext"] = pkg.ciphertext

    with pytest.raises(CiphertextAuthFailedError):
        decrypt_and_verify_evidence(dict_pkg, None, kp)


def test_tampered_digest_fails_with_digest_mismatch():
    kp = LocalSimulatedVaultProvider()
    original = b"Judge ruling on evidence admissibility"
    pkg = encrypt_evidence_bytes(original, "CAS-10", "DOC-20", "v1", kp, "key-transit")

    dict_pkg = pkg.to_metadata_dict()
    dict_pkg["ciphertext"] = pkg.ciphertext
    dict_pkg["nonce"] = pkg.nonce
    dict_pkg["tag"] = pkg.tag

    # Tamper with expected digest to something else
    dict_pkg["digest"] = "0" * 64

    # Note: Because digest is also bound in AAD, altering it in package dict
    # causes AAD reconstruction to differ -> GCM authentication fails first!
    with pytest.raises(CiphertextAuthFailedError):
        decrypt_and_verify_evidence(dict_pkg, None, kp)
