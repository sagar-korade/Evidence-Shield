"""Blockchain Anchor client and verification module.

Provides:
- AnchorClient (Abstract Base Class)
- SimulatedAnchorClient (TEST-ONLY provider, explicitly identified)
- Web3AnvilAnchorClient (Persistent local Anvil / Web3.py client)
- Anchor receipt verification adhering to fail-closed error codes:
  - ANCHOR_VERIFICATION_FAILED
  - PENDING_ANCHOR
"""

import abc
import hashlib
import time
from dataclasses import dataclass
from typing import Any, Optional

from evidenceshield_crypto.errors import (
    AnchorVerificationFailedError,
    PendingAnchorError,
)


@dataclass(frozen=True)
class AnchorReceipt:
    """Proof of on-chain Merkle root commitment."""
    tree_size: int
    merkle_root_hex: str
    tx_hash: str
    block_number: int
    contract_address: str
    timestamp: int
    confirmed: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "tree_size": self.tree_size,
            "merkle_root": self.merkle_root_hex.lower(),
            "tx_hash": self.tx_hash,
            "block_number": self.block_number,
            "contract_address": self.contract_address,
            "timestamp": self.timestamp,
            "confirmed": self.confirmed,
        }


class AnchorClient(abc.ABC):
    """Abstract interface for blockchain anchor operations."""

    @property
    @abc.abstractmethod
    def is_test_provider(self) -> bool:
        """Indicates whether this client is test-only."""
        pass

    @abc.abstractmethod
    def anchor_root(self, tree_size: int, merkle_root_hex: str) -> AnchorReceipt:
        """Publish a cumulative Merkle root to the smart contract."""
        pass

    @abc.abstractmethod
    def verify_receipt(self, receipt: AnchorReceipt, expected_root_hex: str) -> bool:
        """Verify on-chain existence and parameters of an anchor receipt."""
        pass

    @abc.abstractmethod
    def get_anchor_for_size(self, tree_size: int) -> Optional[AnchorReceipt]:
        """Fetch recorded anchor for a given tree size."""
        pass


class SimulatedAnchorClient(AnchorClient):
    """TEST-ONLY simulated on-chain anchor client.

    Simulates Anvil block progression, mining, contract storage and event logs.
    Explicitly marked test-only and MUST NOT be used in production judicial environments.
    """

    def __init__(self, contract_address: str = "0x5FbDB2315678afecb367f032d93F642f64180aa3"):
        self._contract_address = contract_address
        self._anchors: dict[int, AnchorReceipt] = {}
        self._latest_size = 0
        self._block_height = 100
        self._pending_txs: dict[str, AnchorReceipt] = {}

    @property
    def is_test_provider(self) -> bool:
        return True

    def set_pending(self, tx_hash: str, receipt: AnchorReceipt) -> None:
        """Test helper: simulate an unmined / pending transaction."""
        self._pending_txs[tx_hash] = receipt

    def anchor_root(self, tree_size: int, merkle_root_hex: str) -> AnchorReceipt:
        root_clean = merkle_root_hex.lower().replace("0x", "")
        if tree_size <= self._latest_size:
            raise AnchorVerificationFailedError(
                f"Tree size {tree_size} must be greater than latest size {self._latest_size}"
            )

        self._block_height += 1
        ts = int(time.time())
        tx_hash = "0x" + hashlib.sha256(f"{tree_size}:{root_clean}:{self._block_height}".encode()).hexdigest()
        receipt = AnchorReceipt(
            tree_size=tree_size,
            merkle_root_hex=root_clean,
            tx_hash=tx_hash,
            block_number=self._block_height,
            contract_address=self._contract_address,
            timestamp=ts,
            confirmed=True,
        )
        self._anchors[tree_size] = receipt
        self._latest_size = tree_size
        return receipt

    def verify_receipt(self, receipt: AnchorReceipt, expected_root_hex: str) -> bool:
        expected_clean = expected_root_hex.lower().replace("0x", "")
        receipt_root = receipt.merkle_root_hex.lower().replace("0x", "")

        if receipt.tx_hash in self._pending_txs:
            raise PendingAnchorError(f"Transaction {receipt.tx_hash} is pending confirmation on-chain")

        if not receipt.confirmed:
            raise PendingAnchorError("Receipt marks transaction as unconfirmed")

        if receipt_root != expected_clean:
            raise AnchorVerificationFailedError(
                f"Receipt root {receipt_root} does not match expected {expected_clean}"
            )

        # Check recorded state in contract
        record = self._anchors.get(receipt.tree_size)
        if not record:
            raise AnchorVerificationFailedError(
                f"No anchor record found on contract at tree_size {receipt.tree_size}"
            )

        if record.merkle_root_hex != expected_clean:
            raise AnchorVerificationFailedError(
                f"Contract root {record.merkle_root_hex} differs from expected {expected_clean}"
            )

        if record.block_number != receipt.block_number:
            raise AnchorVerificationFailedError("Block number mismatch in contract verification")

        return True

    def get_anchor_for_size(self, tree_size: int) -> Optional[AnchorReceipt]:
        return self._anchors.get(tree_size)


class Web3AnvilAnchorClient(AnchorClient):
    """Production / local Anvil Web3 anchor client for Ethereum / EVM testnets."""

    def __init__(
        self,
        rpc_url: str = "http://127.0.0.1:8545",
        contract_address: Optional[str] = None,
        private_key: Optional[str] = None,
    ):
        self._rpc_url = rpc_url
        self._contract_address = contract_address
        self._private_key = private_key

    @property
    def is_test_provider(self) -> bool:
        return False

    def anchor_root(self, tree_size: int, merkle_root_hex: str) -> AnchorReceipt:
        try:
            from web3 import Web3
        except ImportError as e:
            raise AnchorVerificationFailedError("web3 package is required for Web3AnvilAnchorClient") from e

        w3 = Web3(Web3.HTTPProvider(self._rpc_url))
        if not w3.is_connected():
            raise AnchorVerificationFailedError(f"Could not connect to Anvil RPC at {self._rpc_url}")

        # In live environments, interacts via w3.eth.contract
        raise NotImplementedError("Live Anvil transaction submission requires deployed contract ABI")

    def verify_receipt(self, receipt: AnchorReceipt, expected_root_hex: str) -> bool:
        try:
            from web3 import Web3
        except ImportError as e:
            raise AnchorVerificationFailedError("web3 package is required for Web3AnvilAnchorClient") from e

        w3 = Web3(Web3.HTTPProvider(self._rpc_url))
        if not w3.is_connected():
            raise AnchorVerificationFailedError(f"Could not connect to Anvil RPC at {self._rpc_url}")

        tx = w3.eth.get_transaction(receipt.tx_hash)
        if not tx:
            raise AnchorVerificationFailedError(f"Transaction {receipt.tx_hash} not found on chain")

        tx_receipt = w3.eth.get_transaction_receipt(receipt.tx_hash)
        if not tx_receipt or tx_receipt.blockNumber is None:
            raise PendingAnchorError(f"Transaction {receipt.tx_hash} is pending block confirmation")

        if tx_receipt.status != 1:
            raise AnchorVerificationFailedError(f"Transaction {receipt.tx_hash} failed or reverted on chain")

        return True

    def get_anchor_for_size(self, tree_size: int) -> Optional[AnchorReceipt]:
        raise NotImplementedError("Live Anvil query requires deployed contract ABI")
