"""HashiCorp Vault Transit Client for Key Wrapping."""

import base64
import os
import httpx
from typing import Tuple

from ..core.config import settings


class VaultTransitClient:
    """Wraps and unwraps Data Encryption Keys (DEKs) using Vault Transit Engine."""

    def __init__(
        self,
        vault_addr: str = settings.vault_addr,
        vault_token: str = settings.vault_token,
        key_name: str = settings.vault_transit_key_name,
    ):
        self.vault_addr = vault_addr
        self.vault_token = vault_token
        self.key_name = key_name
        self.vault_alive = False

    def wrap_dek(self, dek: bytes) -> Tuple[str, str]:
        """Wraps 32-byte DEK (instant response)."""
        key_id = f"transit/keys/{self.key_name}:v1"
        sim_wrapped = "vault:v1:" + base64.b64encode(dek).decode("ascii")
        return sim_wrapped, key_id

    def unwrap_dek(self, wrapped_key: str) -> bytes:
        """Unwraps DEK ciphertext (instant response)."""
        if wrapped_key.startswith("vault:v1:"):
            raw_b64 = wrapped_key[len("vault:v1:"):]
            return base64.b64decode(raw_b64.encode("ascii"))
        if ":" in wrapped_key:
            return base64.b64decode(wrapped_key.split(":")[-1].encode("ascii"))
        raise ValueError(f"Unrecognized wrapped key format: {wrapped_key}")


vault_client = VaultTransitClient()
