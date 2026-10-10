// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title EvidenceAnchor
 * @notice Tamper-evident on-chain anchor contract for EvidenceShield AI Merkle log roots.
 * @dev Deployed on persistent local Anvil / EVM network to provide independent timestamped
 * attestation for cumulative Merkle roots.
 */
contract EvidenceAnchor {
    struct AnchorRecord {
        bytes32 merkleRoot;
        uint256 timestamp;
        uint256 blockNumber;
        address anchorer;
    }

    // Mapping from treeSize to AnchorRecord
    mapping(uint256 => AnchorRecord) private _anchors;

    // Reverse mapping from merkleRoot to treeSize
    mapping(bytes32 => uint256) private _rootToTreeSize;

    // Latest anchored tree size
    uint256 public latestTreeSize;

    // Total number of anchors committed
    uint256 public anchorCount;

    // Owner / operator address
    address public owner;

    // Events
    event MerkleRootAnchored(
        uint256 indexed treeSize,
        bytes32 indexed merkleRoot,
        uint256 timestamp,
        uint256 blockNumber,
        address indexed anchorer
    );

    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );

    error InvalidTreeSize(uint256 requestedSize, uint256 currentLatestSize);
    error ZeroMerkleRoot();
    error RootAlreadyAnchored(bytes32 root, uint256 existingTreeSize);
    error Unauthorized();

    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert Unauthorized();
        }
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /**
     * @notice Commits a cumulative Merkle root to the ledger.
     * @param treeSize Total number of leaves represented by this root (must be > latestTreeSize).
     * @param merkleRoot SHA-256 root hash of the RFC 9162 Merkle tree.
     */
    function anchorMerkleRoot(uint256 treeSize, bytes32 merkleRoot) external returns (bool) {
        if (merkleRoot == bytes32(0)) {
            revert ZeroMerkleRoot();
        }
        if (treeSize <= latestTreeSize) {
            revert InvalidTreeSize(treeSize, latestTreeSize);
        }
        if (_rootToTreeSize[merkleRoot] != 0) {
            revert RootAlreadyAnchored(merkleRoot, _rootToTreeSize[merkleRoot]);
        }

        AnchorRecord memory record = AnchorRecord({
            merkleRoot: merkleRoot,
            timestamp: block.timestamp,
            blockNumber: block.number,
            anchorer: msg.sender
        });

        _anchors[treeSize] = record;
        _rootToTreeSize[merkleRoot] = treeSize;
        latestTreeSize = treeSize;
        anchorCount += 1;

        emit MerkleRootAnchored(
            treeSize,
            merkleRoot,
            block.timestamp,
            block.number,
            msg.sender
        );

        return true;
    }

    /**
     * @notice Fetch anchor record for a specific tree size.
     */
    function getAnchor(uint256 treeSize) external view returns (
        bytes32 merkleRoot,
        uint256 timestamp,
        uint256 blockNumber,
        address anchorer
    ) {
        AnchorRecord memory record = _anchors[treeSize];
        return (
            record.merkleRoot,
            record.timestamp,
            record.blockNumber,
            record.anchorer
        );
    }

    /**
     * @notice Fetch latest committed anchor record.
     */
    function getLatestAnchor() external view returns (
        uint256 treeSize,
        bytes32 merkleRoot,
        uint256 timestamp,
        uint256 blockNumber,
        address anchorer
    ) {
        AnchorRecord memory record = _anchors[latestTreeSize];
        return (
            latestTreeSize,
            record.merkleRoot,
            record.timestamp,
            record.blockNumber,
            record.anchorer
        );
    }

    /**
     * @notice Check whether a given root has been anchored.
     */
    function isRootAnchored(bytes32 root) external view returns (bool) {
        return _rootToTreeSize[root] != 0;
    }

    /**
     * @notice Lookup tree size for an anchored root.
     */
    function getTreeSizeForRoot(bytes32 root) external view returns (uint256) {
        return _rootToTreeSize[root];
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) {
            revert Unauthorized();
        }
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
