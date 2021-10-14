// SPDX-License-Identifier: UNLICENSED
pragma abicoder v2;
pragma solidity 0.8.0;

contract UnirepParameters {
    // This structs help to reduce the number of parameters to the constructor
    // and avoid a stack overflow error during compilation
    struct TreeDepths {
        uint8 globalStateTreeDepth;
        uint8 userStateTreeDepth;
        uint8 epochTreeDepth;
    }

    struct MaxValues {
        uint256 maxUsers;
        uint256 maxAttesters;
    }

    struct ProofsRelated {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
        bool isValid;
    }

    struct EpochKeyProofRelated{
        uint256 globalStateTree;
        uint256 epoch;
        uint256 epochKey;
        uint256[8] proof;
    }

    struct SignUpProofRelated{
        uint256 epoch;
        uint256 epochKey;
        uint256 globalStateTree;
        uint256 attesterId;
        uint256[8] proof;
    }

    struct UserTransitionedRelated{
        uint256 newGlobalStateTreeLeaf;
        uint256[] epkNullifiers;
        uint256 transitionFromEpoch;
        uint256[] blindedUserStates;
        uint256 fromGlobalStateTree;
        uint256[] blindedHashChains;
        uint256 fromEpochTree;
        uint256[8] proof;
    }

    struct ReputationProofRelated{
        uint256[] repNullifiers;
        uint256 epoch;
        uint256 epochKey;
        uint256 globalStateTree;
        uint256 attesterId;
        uint256 proveReputationAmount;
        uint256 minRep;
        uint256 proveGraffiti;
        uint256 graffitiPreImage;
        uint256[8] proof;
    }
}