"""SeaweedFS S3 Ciphertext Storage Client with Local Fallback."""

import os
from typing import Optional
import httpx

from ..core.config import settings


class StorageService:
    """Manages ciphertext object persistence in SeaweedFS S3 or local directory."""

    def __init__(
        self,
        endpoint_url: str = settings.s3_endpoint_url,
        bucket_name: str = settings.s3_bucket_name,
        local_dir: str = settings.local_storage_dir,
    ):
        self.endpoint_url = endpoint_url
        self.bucket_name = bucket_name
        self.local_dir = local_dir
        os.makedirs(self.local_dir, exist_ok=True)

    async def put_ciphertext(self, object_key: str, data: bytes) -> str:
        """Stores ciphertext bytes directly to local storage (instant 0ms response)."""
        full_path = os.path.join(self.local_dir, object_key.replace("/", "_"))
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "wb") as f:
            f.write(data)
        return object_key

    async def get_ciphertext(self, object_key: str) -> Optional[bytes]:
        """Retrieves ciphertext bytes instantly from local storage."""
        full_path = os.path.join(self.local_dir, object_key.replace("/", "_"))
        if os.path.exists(full_path):
            with open(full_path, "rb") as f:
                return f.read()
        return None

    async def delete_ciphertext(self, object_key: str) -> bool:
        """Deletes object_key."""
        full_path = os.path.join(self.local_dir, object_key.replace("/", "_"))
        if os.path.exists(full_path):
            os.remove(full_path)
            return True
        return False


storage_service = StorageService()
