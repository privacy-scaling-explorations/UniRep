// SPDX-License-Identifier: UNLICENSED
pragma abicoder v2;
pragma solidity 0.8.0;

import { Hasher } from "./Hasher.sol";
import { UnirepParameters } from "./UnirepParameters.sol";

contract DomainObjs is Hasher, UnirepParameters {
    struct StateLeaf {
        uint256 identityCommitment;
        uint256 userStateRoot;
    }

    function hashStateLeaf(StateLeaf memory _stateLeaf) public pure returns (uint256) {
        return hashLeftRight(_stateLeaf.identityCommitment, _stateLeaf.userStateRoot);
    }

    function hashAirdroppedLeaf(uint256 airdropPosRep) public pure returns (uint256) {
        uint256[5] memory airdroppedLeafValues;
        uint256 hasSignedUp = 1;
        airdroppedLeafValues[0] = airdropPosRep;
        airdroppedLeafValues[3] = hasSignedUp;
        return hash5(airdroppedLeafValues);
    }

    function hashEpochKeyProof(EpochKeyProofRelated memory epochKeyProofData) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            epochKeyProofData.globalStateTree, 
            epochKeyProofData.epoch, 
            epochKeyProofData.epochKey, 
            epochKeyProofData.proof
            )
        );
    }

    function hashReputationProof(ReputationProofRelated memory reputationProofData) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            reputationProofData.repNullifiers, 
            reputationProofData.epoch, 
            reputationProofData.epochKey, 
            reputationProofData.globalStateTree, 
            reputationProofData.attesterId, 
            reputationProofData.proveReputationAmount,
            reputationProofData.minRep, 
            reputationProofData.proveGraffiti, 
            reputationProofData.graffitiPreImage, 
            reputationProofData.proof
            )
        );
    }

    function hashSignUpProof(SignUpProofRelated memory signUpProofData) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            signUpProofData.epoch, 
            signUpProofData.epochKey, 
            signUpProofData.globalStateTree, 
            signUpProofData.attesterId, 
            signUpProofData.proof
            )
        );
    }

    function hashStartTransitionProof(uint256 _blindedUserState, uint256 _blindedHashChain, uint256 _globalStateTree, uint256[8] memory _proof) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            _blindedUserState, 
            _blindedHashChain, 
            _globalStateTree, 
            _proof
            )
        );
    }
    
    function hashProcessAttestationsProof(
        uint256 _outputBlindedUserState,
        uint256 _outputBlindedHashChain,
        uint256 _inputBlindedUserState,
        uint256[8] calldata _proof) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            _outputBlindedUserState, 
            _outputBlindedHashChain, 
            _inputBlindedUserState, 
            _proof
            )
        );
    }

    function hashUserStateTransitionProof(UserTransitionedRelated memory userTransitionedData) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            userTransitionedData.newGlobalStateTreeLeaf, 
            userTransitionedData.epkNullifiers, 
            userTransitionedData.transitionFromEpoch, 
            userTransitionedData.blindedUserStates, 
            userTransitionedData.fromGlobalStateTree, userTransitionedData.blindedHashChains, 
            userTransitionedData.fromEpochTree, 
            userTransitionedData.proof)
        );
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
        // A flag to indicate if user has signed up in this leaf
        uint256 signUp;
    }

    function hashAttestation(Attestation memory attestation) internal pure returns (uint256) {
        uint256[5] memory attestationData;
        attestationData[0] = attestation.attesterId;
        attestationData[1] = attestation.posRep;
        attestationData[2] = attestation.negRep;
        attestationData[3] = attestation.graffiti;
        attestationData[4] = attestation.signUp;
        return hash5(attestationData);
    }
}