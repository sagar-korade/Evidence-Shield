"""Key Provider and Vault Transit abstraction module.

Provides dependency injection interfaces for cryptographic operations:
- Key wrapping / unwrapping (AES-256 Key Encryption Key)
- Asymmetric signing / verification (Ed25519)

Includes:
- KeyProvider (Abstract Base Class)
- LocalSimulatedVaultProvider (TEST-ONLY provider, explicitly marked)
- VaultTransitClient (Production HashiCorp Vault Transit client)
"""

import abc
import base64
import os
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from evidenceshield_crypto.errors import (
    InvalidSignatureError,
    UnsupportedFormatOrKeyError,
)


class KeyProvider(abc.ABC):
    """Abstract dependency-injected key provider interface."""

    @property
    @abc.abstractmethod
    def is_test_provider(self) -> bool:
        """Indicates whether this provider is test-only and forbidden in production."""
        pass

    @abc.abstractmethod
    def wrap_key(self, dek: bytes, key_name: str) -> str:
        """Wrap a 256-bit data encryption key under the named transit key.

        Returns string formatted as 'vault:v<version>:<base64-ciphertext>'.
        """
        pass

    @abc.abstractmethod
    def unwrap_key(self, wrapped_key: str, key_name: str) -> bytes:
        """Unwrap a wrapped DEK using the named transit key.

        Returns raw 32-byte data encryption key.
        """
        pass

    @abc.abstractmethod
    def sign(self, message: bytes, key_name: str) -> bytes:
        """Sign canonical message bytes using the named transit signing key (Ed25519)."""
        pass

    @abc.abstractmethod
    def get_public_key_bytes(self, key_name: str) -> bytes:
        """Return 32-byte raw Ed25519 public key for verification."""
        pass


class LocalSimulatedVaultProvider(KeyProvider):
    """TEST-ONLY simulated Vault Transit provider.

    Explicitly identified as a test provider. MUST NOT be used as the default
    in production judicial workflows.
    Uses real in-memory AES-256-GCM for wrapping and real Ed25519 for signing,
    simulating HashiCorp Vault Transit response formats.
    """

    def __init__(self, seed: Optional[bytes] = None):
        self._test_provider = True
        # KEK for wrapping DEKs: 256-bit key
        if seed:
            self._kek = hashlib_kdf(seed, b"kek", 32)
            ed_seed = hashlib_kdf(seed, b"ed25519", 32)
            self._signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(ed_seed)
        else:
            self._kek = os.urandom(32)
            self._signing_key = ed25519.Ed25519PrivateKey.generate()

        self._aesgcm = AESGCM(self._kek)
        self._key_versions: dict[str, int] = {}

    @property
    def is_test_provider(self) -> bool:
        return True

    def wrap_key(self, dek: bytes, key_name: str) -> str:
        if len(dek) != 32:
            raise ValueError("DEK must be exactly 32 bytes (256 bits)")
        version = self._key_versions.get(key_name, 1)
        nonce = os.urandom(12)
        aad = f"vault:transit:{key_name}:v{version}".encode("utf-8")
        ciphertext = self._aesgcm.encrypt(nonce, dek, aad)
        # Pack nonce + ciphertext
        payload = nonce + ciphertext
        encoded = base64.b64encode(payload).decode("ascii")
        return f"vault:v{version}:{encoded}"

    def unwrap_key(self, wrapped_key: str, key_name: str) -> bytes:
        if not wrapped_key.startswith("vault:v"):
            raise UnsupportedFormatOrKeyError(f"Invalid Vault Transit ciphertext header: {wrapped_key[:10]}")
        parts = wrapped_key.split(":")
        if len(parts) != 3:
            raise UnsupportedFormatOrKeyError("Malformed Vault Transit ciphertext string")
        version_str, encoded = parts[1], parts[2]
        try:
            raw = base64.b64decode(encoded)
            if len(raw) < 12 + 16:  # nonce (12) + tag (16)
                raise ValueError("Wrapped payload too short")
            nonce = raw[:12]
            ciphertext = raw[12:]
            aad = f"vault:transit:{key_name}:{version_str}".encode("utf-8")
            dek = self._aesgcm.decrypt(nonce, ciphertext, aad)
            return dek
        except Exception as e:
            raise UnsupportedFormatOrKeyError(f"Failed to unwrap DEK under key '{key_name}': {e}") from e

    def sign(self, message: bytes, key_name: str) -> bytes:
        return self._signing_key.sign(message)

    def get_public_key_bytes(self, key_name: str) -> bytes:
        return self._signing_key.public_key().public_bytes_raw()


def hashlib_kdf(secret: bytes, salt: bytes, length: int) -> bytes:
    """Deterministic KDF for simulated provider test reproducibility."""
    import hashlib
    out = b""
    counter = 1
    while len(out) < length:
        h = hashlib.sha256(secret + salt + counter.to_bytes(4, "big")).digest()
        out += h
        counter += 1
    return out[:length]


class VaultTransitClient(KeyProvider):
    """Production HashiCorp Vault Transit API KeyProvider.

    Interfaces with HashiCorp Vault Transit secrets engine over HTTPS.
    Requires VAULT_ADDR and VAULT_TOKEN configuration.
    """

    def __init__(
        self,
        vault_addr: str,
        vault_token: str,
        mount_path: str = "transit",
        verify_tls: bool = True,
    ):
        self._vault_addr = vault_addr.rstrip("/")
        self._vault_token = vault_token
        self._mount_path = mount_path
        self._verify_tls = verify_tls

    @property
    def is_test_provider(self) -> bool:
        return False

    def wrap_key(self, dek: bytes, key_name: str) -> str:
        """Call Vault Transit /encrypt endpoint with base64 plaintext DEK."""
        import urllib.request
        import json

        url = f"{self._vault_addr}/v1/{self._mount_path}/encrypt/{key_name}"
        b64_plaintext = base64.b64encode(dek).decode("ascii")
        req_data = json.dumps({"plaintext": b64_plaintext}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=req_data,
            headers={
                "X-Vault-Token": self._vault_token,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["data"]["ciphertext"]
        except Exception as e:
            raise UnsupportedFormatOrKeyError(f"Vault wrap_key failed for '{key_name}': {e}") from e

    def unwrap_key(self, wrapped_key: str, key_name: str) -> bytes:
        """Call Vault Transit /decrypt endpoint."""
        import urllib.request
        import json

        url = f"{self._vault_addr}/v1/{self._mount_path}/decrypt/{key_name}"
        req_data = json.dumps({"ciphertext": wrapped_key}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=req_data,
            headers={
                "X-Vault-Token": self._vault_token,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                b64_plaintext = data["data"]["plaintext"]
                return base64.b64decode(b64_plaintext)
        except Exception as e:
            raise UnsupportedFormatOrKeyError(f"Vault unwrap_key failed for '{key_name}': {e}") from e

    def sign(self, message: bytes, key_name: str) -> bytes:
        """Call Vault Transit /sign endpoint for Ed25519 signing."""
        import urllib.request
        import json

        url = f"{self._vault_addr}/v1/{self._mount_path}/sign/{key_name}/sha2-256"
        b64_input = base64.b64encode(message).decode("ascii")
        req_data = json.dumps({"input": b64_input, "signature_algorithm": "ed25519"}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=req_data,
            headers={
                "X-Vault-Token": self._vault_token,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                vault_sig = data["data"]["signature"]  # vault:v1:base64...
                b64_sig = vault_sig.split(":")[-1]
                return base64.b64decode(b64_sig)
        except Exception as e:
            raise UnsupportedFormatOrKeyError(f"Vault sign failed for '{key_name}': {e}") from e

    def get_public_key_bytes(self, key_name: str) -> bytes:
        """Call Vault Transit /keys endpoint to fetch public key."""
        import urllib.request
        import json

        url = f"{self._vault_addr}/v1/{self._mount_path}/keys/{key_name}"
        req = urllib.request.Request(
            url,
            headers={"X-Vault-Token": self._vault_token},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                # Get latest key version
                keys = data["data"]["keys"]
                latest_ver = str(max(int(k) for k in keys.keys()))
                b64_pub = keys[latest_ver]["public_key"]
                return base64.b64decode(b64_pub)
        except Exception as e:
            raise UnsupportedFormatOrKeyError(f"Vault get_public_key failed for '{key_name}': {e}") from e
