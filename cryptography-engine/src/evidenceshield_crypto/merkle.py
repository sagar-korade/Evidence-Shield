"""RFC 9162 Domain-Separated SHA-256 Merkle Tree implementation.

Features:
- Leaf hashing: SHA-256(0x00 || leaf_data)
- Internal-node hashing: SHA-256(0x01 || left_hash || right_hash)
- Split rule: k = largest power of 2 smaller than n (k = 2^floor(log2(n - 1)))
- No last-leaf duplication for odd trees.
- Full RFC 9162 Inclusion Proof generation and fail-closed verification.
- Full RFC 9162 Consistency Proof generation and fail-closed verification.
"""

import hashlib
import math
from typing import Optional, Sequence, Union

from evidenceshield_crypto.errors import (
    InvalidConsistencyProofError,
    InvalidInclusionProofError,
)

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def largest_power_of_two_less_than(n: int) -> int:
    """Return the largest power of 2 less than n (for n > 1).

    k = 2^(floor(log2(n - 1)))
    """
    if n <= 1:
        raise ValueError(f"n must be > 1, got {n}")
    # Equivalent to 1 << (n - 1).bit_length() - 1
    return 1 << ((n - 1).bit_length() - 1)


def hash_leaf(data: bytes) -> bytes:
    """Compute RFC 9162 domain-separated leaf hash: SHA-256(0x00 || data)."""
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def hash_children(left: bytes, right: bytes) -> bytes:
    """Compute RFC 9162 domain-separated internal node hash: SHA-256(0x01 || left || right)."""
    if len(left) != 32 or len(right) != 32:
        raise ValueError(f"Child hashes must be 32 bytes each, got {len(left)} and {len(right)}")
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


class RFC9162MerkleTree:
    """In-memory RFC 9162 Cumulative Merkle Tree."""

    def __init__(self, leaves: Optional[Sequence[bytes]] = None, raw_leaves: bool = True):
        """Initialize Merkle tree.

        If raw_leaves=True, items in leaves are hashed using hash_leaf(data).
        If raw_leaves=False, items in leaves are assumed to already be 32-byte leaf hashes.
        """
        self._leaf_hashes: list[bytes] = []
        if leaves:
            for item in leaves:
                if raw_leaves:
                    self._leaf_hashes.append(hash_leaf(item))
                else:
                    if len(item) != 32:
                        raise ValueError(f"Leaf hash must be 32 bytes, got {len(item)}")
                    self._leaf_hashes.append(item)

    @property
    def tree_size(self) -> int:
        return len(self._leaf_hashes)

    @property
    def leaf_hashes(self) -> list[bytes]:
        return list(self._leaf_hashes)

    def append_leaf(self, data: bytes, is_prehashed_leaf: bool = False) -> int:
        """Append a leaf to the tree and return its 0-indexed leaf position."""
        if is_prehashed_leaf:
            if len(data) != 32:
                raise ValueError("Prehashed leaf must be 32 bytes")
            leaf_h = data
        else:
            leaf_h = hash_leaf(data)
        idx = len(self._leaf_hashes)
        self._leaf_hashes.append(leaf_h)
        return idx

    def get_root_hash(self, size: Optional[int] = None) -> bytes:
        """Compute the Merkle Tree Hash (MTH) for the first `size` leaves."""
        n = len(self._leaf_hashes) if size is None else size
        if n < 0 or n > len(self._leaf_hashes):
            raise ValueError(f"Invalid size {size} for tree with {len(self._leaf_hashes)} leaves")
        return self._sub_root(0, n)

    def _sub_root(self, start: int, end: int) -> bytes:
        n = end - start
        if n == 0:
            return hashlib.sha256(b"").digest()
        if n == 1:
            return self._leaf_hashes[start]
        k = largest_power_of_two_less_than(n)
        left = self._sub_root(start, start + k)
        right = self._sub_root(start + k, end)
        return hash_children(left, right)

    def get_inclusion_proof(self, leaf_index: int, tree_size: Optional[int] = None) -> list[bytes]:
        """Generate RFC 9162 inclusion proof (audit path) for leaf at leaf_index."""
        n = len(self._leaf_hashes) if tree_size is None else tree_size
        if not (0 <= leaf_index < n):
            raise ValueError(f"leaf_index {leaf_index} out of range [0, {n})")
        return self._build_inclusion_path(leaf_index, 0, n)

    def _build_inclusion_path(self, m: int, start: int, end: int) -> list[bytes]:
        n = end - start
        if n == 1:
            return []
        k = largest_power_of_two_less_than(n)
        if m < k:
            path = self._build_inclusion_path(m, start, start + k)
            sibling = self._sub_root(start + k, end)
            path.append(sibling)
            return path
        else:
            path = self._build_inclusion_path(m - k, start + k, end)
            sibling = self._sub_root(start, start + k)
            path.append(sibling)
            return path

    def get_consistency_proof(self, m: int, n: Optional[int] = None) -> list[bytes]:
        """Generate RFC 9162 consistency proof between tree size m and n."""
        tree_n = len(self._leaf_hashes) if n is None else n
        if not (0 <= m <= tree_n):
            raise ValueError(f"Invalid sizes for consistency proof: m={m}, n={tree_n}")
        if m == 0 or m == tree_n:
            return []
        return self._build_subproof(m, 0, tree_n, b=True)

    def _build_subproof(self, m: int, start: int, end: int, b: bool) -> list[bytes]:
        n = end - start
        if m == n:
            if b:
                return []
            return [self._sub_root(start, end)]
        k = largest_power_of_two_less_than(n)
        if m <= k:
            path = self._build_subproof(m, start, start + k, b)
            sibling = self._sub_root(start + k, end)
            path.append(sibling)
            return path
        else:
            path = self._build_subproof(m - k, start + k, end, False)
            sibling = self._sub_root(start, start + k)
            path.append(sibling)
            return path


def verify_inclusion_proof(
    leaf_hash: bytes,
    leaf_index: int,
    tree_size: int,
    proof: Sequence[bytes],
    expected_root: bytes,
) -> bool:
    """Verify RFC 9162 Merkle inclusion proof against expected root.

    Raises InvalidInclusionProofError if verification fails.
    """
    if len(leaf_hash) != 32:
        raise InvalidInclusionProofError(f"Leaf hash must be 32 bytes, got {len(leaf_hash)}")
    if len(expected_root) != 32:
        raise InvalidInclusionProofError(f"Expected root must be 32 bytes, got {len(expected_root)}")
    if not (0 <= leaf_index < tree_size):
        raise InvalidInclusionProofError(f"Invalid leaf_index {leaf_index} for tree_size {tree_size}")

    # Trace top-down path from root to leaf to determine sibling positions
    # Returns list of (sibling_is_left: bool) from root down to leaf
    choices: list[bool] = []
    curr_idx = leaf_index
    curr_size = tree_size
    while curr_size > 1:
        k = largest_power_of_two_less_than(curr_size)
        if curr_idx < k:
            # target is in left child, sibling is on the right
            choices.append(False)  # sibling_is_right
            curr_size = k
        else:
            # target is in right child, sibling is on the left
            choices.append(True)   # sibling_is_left
            curr_idx -= k
            curr_size = curr_size - k

    if len(proof) != len(choices):
        raise InvalidInclusionProofError(
            f"Proof length {len(proof)} does not match expected path length {len(choices)}"
        )

    # In RFC 9162, path list has bottom-most sibling first (deepest level)
    # choices was collected top-down, so reverse choices to go bottom-up
    rev_choices = list(reversed(choices))

    current = leaf_hash
    for sibling, sibling_is_left in zip(proof, rev_choices):
        if len(sibling) != 32:
            raise InvalidInclusionProofError(f"Sibling hash must be 32 bytes, got {len(sibling)}")
        if sibling_is_left:
            current = hash_children(sibling, current)
        else:
            current = hash_children(current, sibling)

    if current != expected_root:
        raise InvalidInclusionProofError(
            f"Calculated root ({current.hex()}) does not match expected root ({expected_root.hex()})"
        )
    return True


def verify_consistency_proof(
    m: int,
    n: int,
    root1: bytes,
    root2: bytes,
    proof: Sequence[bytes],
) -> bool:
    """Verify RFC 9162 Merkle tree consistency proof between size m and n.

    Proves tree of size m is an exact prefix of tree of size n (0 < m <= n).
    Raises InvalidConsistencyProofError if verification fails.
    """
    if not (0 < m <= n):
        raise InvalidConsistencyProofError(f"Invalid tree sizes: m={m}, n={n}")
    if len(root1) != 32 or len(root2) != 32:
        raise InvalidConsistencyProofError("Roots must be 32 bytes each")

    if m == n:
        if len(proof) != 0:
            raise InvalidConsistencyProofError("Consistency proof for m == n must be empty")
        if root1 != root2:
            raise InvalidConsistencyProofError("Roots do not match for m == n")
        return True

    # Reconstruct both root1 and root2 from consistency proof according to RFC 9162
    # Algorithm per RFC 9162 Section 2.1.4:
    # 1. If m is a power of 2, set node = root1, otherwise node = proof[0]
    proof_list = list(proof)
    if not proof_list:
        raise InvalidConsistencyProofError("Non-empty proof required for m < n")

    is_power_of_two = (m & (m - 1)) == 0
    if is_power_of_two:
        calc_root1 = root1
        calc_root2 = root1
    else:
        calc_root1 = proof_list[0]
        calc_root2 = proof_list[0]
        proof_list = proof_list[1:]

    fn = m - 1
    sn = n - 1
    while (fn & 1) != 0:
        fn >>= 1
        sn >>= 1

    for p in proof_list:
        if len(p) != 32:
            raise InvalidConsistencyProofError("Proof node must be 32 bytes")
        if sn == 0:
            raise InvalidConsistencyProofError("Proof has more elements than expected")
        if (fn & 1) != 0 or fn == sn:
            calc_root1 = hash_children(p, calc_root1)
            calc_root2 = hash_children(p, calc_root2)
            while (fn & 1) == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            calc_root2 = hash_children(calc_root2, p)
        fn >>= 1
        sn >>= 1

    if calc_root1 != root1:
        raise InvalidConsistencyProofError(
            f"Consistency proof root1 mismatch: calculated {calc_root1.hex()}, expected {root1.hex()}"
        )
    if calc_root2 != root2:
        raise InvalidConsistencyProofError(
            f"Consistency proof root2 mismatch: calculated {calc_root2.hex()}, expected {root2.hex()}"
        )
    return True
