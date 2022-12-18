// https://tornado.cash
/*
 * d888888P                                           dP              a88888b.                   dP
 *    88                                              88             d8'   `88                   88
 *    88    .d8888b. 88d888b. 88d888b. .d8888b. .d888b88 .d8888b.    88        .d8888b. .d8888b. 88d888b.
 *    88    88'  `88 88'  `88 88'  `88 88'  `88 88'  `88 88'  `88    88        88'  `88 Y8ooooo. 88'  `88
 *    88    88.  .88 88       88    88 88.  .88 88.  .88 88.  .88 dP Y8.   .88 88.  .88       88 88    88
 *    dP    `88888P' dP       dP    dP `88888P8 `88888P8 `88888P' 88  Y88888P' `88888P8 `88888P' dP    dP
 * ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo
 */

// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

import "./MerkleTreeWithHistory.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IVerifier {
  function verifyProof(bytes memory _proof, uint256[6] memory _input) external returns (bool);
}

abstract contract Tornado is MerkleTreeWithHistory, ReentrancyGuard {
  IVerifier public immutable verifier;
  address public immutable revokeGovernance;
  uint256 public denomination;

  mapping(bytes32 => bool) public nullifierHashes;
  // we store all commitments just to prevent accidental deposits with the same commitment
  mapping(bytes32 => bool) public commitments;

  event Deposit(bytes32 indexed commitment, uint32 leafIndex, uint256 timestamp);
  event Revoked(bytes32 indexed commitment, uint32 leafIndex, uint256 timestamp);
  event Withdrawal(address to, bytes32 nullifierHash, address indexed relayer, uint256 fee);

  /**
    @dev The constructor
    @param _verifier the address of SNARK verifier for this contract
    @param _hasher the address of MiMC hash contract
    @param _denomination transfer amount for each deposit
    @param _merkleTreeHeight the height of deposits' Merkle Tree
  */
  constructor(
    IVerifier _verifier,
    address _revokeGovernance,
    IHasher _hasher,
    uint256 _denomination,
    uint32 _merkleTreeHeight
  ) MerkleTreeWithHistory(_merkleTreeHeight, _hasher) {
    require(_denomination > 0, "denomination should be greater than 0");
    verifier = _verifier;
    revokeGovernance = _revokeGovernance;
    denomination = _denomination;
  }

  /**
    @dev Deposit funds into the contract. The caller must send (for ETH) or approve (for ERC20) value equal to or `denomination` of this instance.
    @param _commitment the note commitment, which is PedersenHash(nullifier + secret)
  */
  function deposit(bytes32 _commitment) external payable nonReentrant {
    require(!commitments[_commitment], "The commitment has been submitted");

    uint32 insertedIndex = _insert(_commitment);
    commitments[_commitment] = true;
    _processDeposit();

    emit Deposit(_commitment, insertedIndex, block.timestamp);
  }

  /**
    @dev ...
    @param _commitment ...
    TODO: elements are uint256 because in JS hash has reverse byte order than bytes32
    TODO: restrict who can call revoke()
    TODO: must add withdraw delay to ensure commitment wasn't already withdrawn (otherwise revoke would still succeeed but you wouldn't be able to tell)
  */
  function revoke(bytes32 _commitment, bytes32 _lastCommitment, uint32 _index, uint256[] calldata _commitmentElements, uint256[] calldata _newSubtrees) external payable nonReentrant {
    // require(msg.sender == revokeGovernance, "must be revoker!");
    require(commitments[_commitment], "The commitment has not been submitted");

    /*
      - calculate root from commitment proof and compare to lastRoot()
      - revoke commitment by setting leaf to 0
      - calculate new root
      - calculate expected root from lastNode proof
      - verify that lastNode proof matches the updated merkle root
      - if true, update filledSubtrees with lastProof
     */

    // calcuate root from commitment proof
    bytes32 preRevokeRoot = _commitment;
    bytes32 left;
    bytes32 right;
    uint32 currentIndex = _index;

    for (uint32 i = 0; i < levels; i++) {
      if (currentIndex % 2 == 0) {
        left = preRevokeRoot;
        right = bytes32(_commitmentElements[i]);
      } else {
        left = bytes32(_commitmentElements[i]);
        right = preRevokeRoot;
      }
      preRevokeRoot = hashLeftRight(hasher, left, right);
      currentIndex /= 2;
    }

    // verify commitment proof was valid
    require(preRevokeRoot == getLastRoot(), "invalid commitment proof");

    // calculate new root
    bytes32 postRevokeRoot = bytes32(0x0);
    currentIndex = _index;

    for (uint32 i = 0; i < levels; i++) {
      if (currentIndex % 2 == 0) {
        left = postRevokeRoot;
        right = bytes32(_commitmentElements[i]);
      } else {
        left = bytes32(_commitmentElements[i]);
        right = postRevokeRoot;
      }
      postRevokeRoot = hashLeftRight(hasher, left, right);
      currentIndex /= 2;
    }

    // calculate new root to ensure no other elements were modified
    bytes32 postRevokeRootVerification = _lastCommitment;
    currentIndex = nextIndex - 1;

    for (uint32 i = 0; i < levels; i++) {
      // update filledSubtrees with new proof
      filledSubtrees[i] = bytes32(_newSubtrees[i]);
      if (currentIndex % 2 == 0) {
        left = postRevokeRootVerification;
        right = bytes32(_newSubtrees[i]);
      } else {
        left = bytes32(_newSubtrees[i]);
        right = postRevokeRootVerification;
      }
      postRevokeRootVerification = hashLeftRight(hasher, left, right);
      currentIndex /= 2;
    }

    // verify new root to ensure no other elements were modified
    require(postRevokeRootVerification == postRevokeRoot, "merkle tree improperly modified");

    // finally overwrite older roots containing revoked commitment
    for (uint32 i = 0; i < ROOT_HISTORY_SIZE; i++)
      roots[i] = postRevokeRoot;

    // should commitment be erased? I don't see a reason to...
    // commitments[_commitment] = false;
    
    // should withdraw?
    // _processWithdraw(msg.sender, address(0), 0, 0);

    emit Revoked(_commitment, _index, block.timestamp);
  }

  /** @dev this function is defined in a child contract */
  function _processDeposit() internal virtual;

  /**
    @dev Withdraw a deposit from the contract. `proof` is a zkSNARK proof data, and input is an array of circuit public inputs
    `input` array consists of:
      - merkle root of all deposits in the contract
      - hash of unique deposit nullifier to prevent double spends
      - the recipient of funds
      - optional fee that goes to the transaction sender (usually a relay)
  */
  function withdraw(
    bytes calldata _proof,
    bytes32 _root,
    bytes32 _nullifierHash,
    address payable _recipient,
    address payable _relayer,
    uint256 _fee,
    uint256 _refund
  ) external payable nonReentrant {
    require(_fee <= denomination, "Fee exceeds transfer value");
    require(!nullifierHashes[_nullifierHash], "The note has been already spent");
    require(isKnownRoot(_root), "Cannot find your merkle root"); // Make sure to use a recent one
    require(
      verifier.verifyProof(
        _proof,
        [uint256(_root), uint256(_nullifierHash), uint256(_recipient), uint256(_relayer), _fee, _refund]
      ),
      "Invalid withdraw proof"
    );

    nullifierHashes[_nullifierHash] = true;
    _processWithdraw(_recipient, _relayer, _fee, _refund);
    emit Withdrawal(_recipient, _nullifierHash, _relayer, _fee);
  }

  /** @dev this function is defined in a child contract */
  function _processWithdraw(
    address payable _recipient,
    address payable _relayer,
    uint256 _fee,
    uint256 _refund
  ) internal virtual;

  /** @dev whether a note is already spent */
  function isSpent(bytes32 _nullifierHash) public view returns (bool) {
    return nullifierHashes[_nullifierHash];
  }

  /** @dev whether an array of notes is already spent */
  function isSpentArray(bytes32[] calldata _nullifierHashes) external view returns (bool[] memory spent) {
    spent = new bool[](_nullifierHashes.length);
    for (uint256 i = 0; i < _nullifierHashes.length; i++) {
      if (isSpent(_nullifierHashes[i])) {
        spent[i] = true;
      }
    }
  }
}
