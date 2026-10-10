import pytest

from evidenceshield_crypto.errors import (
    InvalidConsistencyProofError,
    InvalidInclusionProofError,
)
from evidenceshield_crypto.merkle import (
    RFC9162MerkleTree,
    hash_children,
    hash_leaf,
    largest_power_of_two_less_than,
    verify_consistency_proof,
    verify_inclusion_proof,
)


def test_split_rule_powers_of_two():
    assert largest_power_of_two_less_than(2) == 1
    assert largest_power_of_two_less_than(3) == 2
    assert largest_power_of_two_less_than(4) == 2
    assert largest_power_of_two_less_than(5) == 4
    assert largest_power_of_two_less_than(7) == 4
    assert largest_power_of_two_less_than(8) == 4
    assert largest_power_of_two_less_than(9) == 8


def test_domain_separation_prefixes():
    data = b"sample leaf"
    leaf_h = hash_leaf(data)
    assert len(leaf_h) == 32

    # Internal node prefix
    node_h = hash_children(leaf_h, leaf_h)
    assert len(node_h) == 32
    # Ensure leaf hash and node hash differ even with same inputs
    assert leaf_h != node_h


def test_odd_trees_no_leaf_duplication():
    # Construct tree of size 3
    d1, d2, d3 = b"doc-1", b"doc-2", b"doc-3"
    tree = RFC9162MerkleTree([d1, d2, d3])
    assert tree.tree_size == 3

    # Manually compute according to RFC 9162:
    # k = 2 for n = 3
    # left = hash_children(hash_leaf(d1), hash_leaf(d2))
    # right = hash_leaf(d3)
    # root = hash_children(left, right)
    h1 = hash_leaf(d1)
    h2 = hash_leaf(d2)
    h3 = hash_leaf(d3)
    expected_left = hash_children(h1, h2)
    expected_root = hash_children(expected_left, h3)

    assert tree.get_root_hash() == expected_root


def test_inclusion_proof_verification_all_sizes():
    for size in [1, 2, 3, 4, 5, 7, 8, 9, 15]:
        leaves = [f"evidence-{i}".encode() for i in range(size)]
        tree = RFC9162MerkleTree(leaves)
        root = tree.get_root_hash()

        for idx in range(size):
            proof = tree.get_inclusion_proof(idx)
            leaf_h = tree.leaf_hashes[idx]
            assert verify_inclusion_proof(leaf_h, idx, size, proof, root)


def test_inclusion_proof_fails_on_tampered_leaf():
    tree = RFC9162MerkleTree([b"A", b"B", b"C", b"D"])
    root = tree.get_root_hash()
    proof = tree.get_inclusion_proof(0)

    tampered_leaf = hash_leaf(b"ATTACKER_CONTENT")
    with pytest.raises(InvalidInclusionProofError):
        verify_inclusion_proof(tampered_leaf, 0, 4, proof, root)


def test_consistency_proofs_across_growth():
    tree = RFC9162MerkleTree([f"record-{i}".encode() for i in range(12)])
    for m in range(1, 12):
        for n in range(m, 12):
            proof = tree.get_consistency_proof(m, n)
            r1 = tree.get_root_hash(m)
            r2 = tree.get_root_hash(n)
            assert verify_consistency_proof(m, n, r1, r2, proof)


def test_consistency_proof_fails_on_tampered_root():
    tree = RFC9162MerkleTree([b"x", b"y", b"z", b"w"])
    proof = tree.get_consistency_proof(2, 4)
    r1 = tree.get_root_hash(2)
    fake_r2 = b"0" * 32

    with pytest.raises(InvalidConsistencyProofError):
        verify_consistency_proof(2, 4, r1, fake_r2, proof)
