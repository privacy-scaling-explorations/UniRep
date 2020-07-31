pragma experimental ABIEncoderV2;
pragma solidity ^0.6.0;

import { Hasher } from "./Hasher.sol";

contract DomainObjs is Hasher {
    struct StateLeaf {
        uint256 identityCommitment;
        uint256 userStateRoot;
    }

    function hashStateLeaf(StateLeaf memory _stateLeaf) public pure returns (uint256) {
        return hashLeftRight(_stateLeaf.identityCommitment, _stateLeaf.userStateRoot);
    }

    function getDefaultRoot(uint256 _treeLevels, uint256 _zeroValue) public pure returns(uint256) {
        uint256 node = _zeroValue;
        for (uint256 i = 1; i < _treeLevels; i ++) {
            node = hashLeftRight(node, node);
        }
        return node;
    }

    struct Attestation {
        // The attester’s ID
        uint256 attesterId;
        // Positive reputation
        uint256 posRep;
        // Negative reputation
        uint256 negRep;
        // A hash of an arbitary string
        uint256 graffiti;
        // Whether or not to overwrite the graffiti in the user’s state
        bool overwriteGraffiti;
    }
}