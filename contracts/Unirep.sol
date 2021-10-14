// SPDX-License-Identifier: UNLICENSED
pragma abicoder v2;
pragma solidity 0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import { DomainObjs } from './DomainObjs.sol';
import { SnarkConstants } from './SnarkConstants.sol';
import { ComputeRoot } from './ComputeRoot.sol';
import { UnirepParameters } from './UnirepParameters.sol';
import { EpochKeyValidityVerifier } from './EpochKeyValidityVerifier.sol';
import { StartTransitionVerifier } from './StartTransitionVerifier.sol';
import { ProcessAttestationsVerifier } from './ProcessAttestationsVerifier.sol';
import { UserStateTransitionVerifier } from './UserStateTransitionVerifier.sol';
import { ReputationVerifier } from './ReputationVerifier.sol';
import { UserSignUpVerifier } from './UserSignUpVerifier.sol';

contract Unirep is DomainObjs, ComputeRoot {
    using SafeMath for uint256;

    // A nothing-up-my-sleeve zero value
    // Should be equal to 16916383162496104613127564537688207714240750091683495371401923915264313510848
    uint256 ZERO_VALUE = uint256(keccak256(abi.encodePacked('Unirep'))) % SNARK_SCALAR_FIELD;

    // Verifier Contracts
    EpochKeyValidityVerifier internal epkValidityVerifier;
    StartTransitionVerifier internal startTransitionVerifier;
    ProcessAttestationsVerifier internal processAttestationsVerifier;
    UserStateTransitionVerifier internal userStateTransitionVerifier;
    ReputationVerifier internal reputationVerifier;
    UserSignUpVerifier internal userSignUpVerifier;

    uint256 public currentEpoch = 1;

    uint256 immutable public epochLength;

    uint256 public latestEpochTransitionTime;

    // To store the Merkle root of a tree with 2 **
    // treeDepths.userStateTreeDepth leaves of value 0
    uint256 public emptyUserStateRoot;

    uint256 immutable public emptyGlobalStateTreeRoot;

    // Maximum number of epoch keys allowed for an user to generate in one epoch
    uint8 immutable public numEpochKeyNoncePerEpoch;

    // Maximum number of reputation nullifiers in a proof
    uint8 immutable public maxReputationBudget;

    // The maximum number of signups allowed
    uint256 immutable public maxUsers;

    // The maximum number of attesters allowed
    uint256 immutable public maxAttesters;

    uint256 public numUserSignUps = 0;

    // The index of all proofs, 
    // 0 is reserved for index not found in getProofIndex
    uint256 internal proofIndex = 1;

    // Mapping of proof nullifiers and the proof index
    mapping(bytes32 => uint256) public getProofIndex;

    mapping(uint256 => bool) public hasUserSignedUp;

    // Fee required for submitting an attestation
    uint256 immutable public attestingFee;
    // Attesting fee collected so far
    uint256 public collectedAttestingFee;
    // Mapping of voluteers that execute epoch transition to compensation they earned
    mapping(address => uint256) public epochTransitionCompensation;

    // A mapping between each attesters’ Ethereum address and their attester ID.
    // Attester IDs are incremental and start from 1.
    // No attesters with and ID of 0 should exist.
    mapping(address => uint256) public attesters;

    uint256 public nextAttesterId = 1;

    // Mapping of the airdrop amount of an attester
    mapping(address => uint256) public airdropAmount;

    TreeDepths public treeDepths;


    // Events
    event Sequencer(
        uint256 indexed _epoch,
        string _event
    );

    event NewGSTLeafInserted(
        uint256 indexed _epoch,
        uint256 _hashedLeaf,
        uint256 _proofIndex
    );

    event AttestationSubmitted(
        uint256 indexed _epoch,
        uint256 indexed _epochKey,
        address indexed _attester,
        Attestation attestation,
        uint256 _proofIndex
    );

    event EpochEnded(uint256 indexed _epoch);

    // This event is emitted when a user first signs up in Unirep
    event UserSignUp(
        uint256 indexed _proofIndex,
        uint256 _identityCommitment,
        uint256 _attesterId,
        uint256 _airdropAmount
    );

    event EpochKeyProof(
        uint256 indexed _proofIndex,
        uint256 indexed _epoch,
        uint256 indexed _epochKey,
        EpochKeyProofRelated epochKeyProofData
    );

    event ReputationNullifierProof(
        uint256 indexed _proofIndex,
        uint256 indexed _epoch,
        uint256 indexed _epochKey,
        ReputationProofRelated reputationProofData
    );

    // This event is emitted if a user wants to prove that he has a signup flag in an attester ID
    event UserSignedUpProof(
        uint256 indexed _proofIndex,
        uint256 indexed _epoch,
        uint256 indexed _epochKey,
        SignUpProofRelated signUpProofData
    );

    event StartedTransitionProof(
        uint256 indexed _proofIndex,
        uint256 indexed _blindedUserState,
        uint256 indexed _globalStateTree,
        uint256 _blindedHashChain,
        uint256[8] _proof
    );

    event ProcessedAttestationsProof(
        uint256 indexed _proofIndex,
        uint256 indexed _inputBlindedUserState,
        uint256 _outputBlindedUserState,
        uint256 _outputBlindedHashChain,
        uint256[8] _proof
    );

    event UserStateTransitionProof(
        uint256 indexed _proofIndex,
        UserTransitionedRelated userTransitionedData,
        uint256[] _proofIndexRecords
    );

    constructor(
        TreeDepths memory _treeDepths,
        MaxValues memory _maxValues,
        EpochKeyValidityVerifier _epkValidityVerifier,
        StartTransitionVerifier _startTransitionVerifier,
        ProcessAttestationsVerifier _processAttestationsVerifier,
        UserStateTransitionVerifier _userStateTransitionVerifier,
        ReputationVerifier _reputationVerifier,
        UserSignUpVerifier _userSignUpVerifier,
        uint8 _numEpochKeyNoncePerEpoch,
        uint8 _maxReputationBudget,
        uint256 _epochLength,
        uint256 _attestingFee
    ) {

        treeDepths = _treeDepths;

        // Set the verifier contracts
        epkValidityVerifier = _epkValidityVerifier;
        startTransitionVerifier = _startTransitionVerifier;
        processAttestationsVerifier = _processAttestationsVerifier;
        userStateTransitionVerifier = _userStateTransitionVerifier;
        reputationVerifier = _reputationVerifier;
        userSignUpVerifier = _userSignUpVerifier;

        numEpochKeyNoncePerEpoch = _numEpochKeyNoncePerEpoch;
        maxReputationBudget = _maxReputationBudget;
        epochLength = _epochLength;
        latestEpochTransitionTime = block.timestamp;

        // Check and store the maximum number of signups
        // It is the user's responsibility to ensure that the state tree depth
        // is just large enough and not more, or they will waste gas.
        uint256 GSTMaxLeafIndex = uint256(2) ** _treeDepths.globalStateTreeDepth - 1;
        require(_maxValues.maxUsers <= GSTMaxLeafIndex, "Unirep: invalid maxUsers value");
        maxUsers = _maxValues.maxUsers;

        uint256 USTMaxLeafIndex = uint256(2) ** _treeDepths.userStateTreeDepth - 1;
        require(_maxValues.maxAttesters <= USTMaxLeafIndex, "Unirep: invalid maxAttesters value");
        maxAttesters = _maxValues.maxAttesters;

        // Calculate and store the empty user state tree root. This value must
        // be set before we compute empty global state tree root later
        emptyUserStateRoot = calcEmptyUserStateTreeRoot(_treeDepths.userStateTreeDepth);
        emptyGlobalStateTreeRoot = calcEmptyGlobalStateTreeRoot(_treeDepths.globalStateTreeDepth);

        attestingFee = _attestingFee;
    }

    /*
     * User signs up by providing an identity commitment. It also inserts a fresh state
     * leaf into the state tree.
     * @param _identityCommitment Commitment of the user's identity which is a semaphore identity.
     */
    function userSignUp(uint256 _identityCommitment) external {
        require(hasUserSignedUp[_identityCommitment] == false, "Unirep: the user has already signed up");
        require(numUserSignUps < maxUsers, "Unirep: maximum number of user signups reached");
        
        uint256 defaultUserStateRoot = emptyUserStateRoot;
        uint256 attesterId = attesters[msg.sender];
        uint256 airdropPosRep = airdropAmount[msg.sender];
        if(attesterId > 0 && airdropPosRep > 0) {
            uint256 airdropLeaf = hashAirdroppedLeaf(airdropPosRep);
            defaultUserStateRoot = calcAirdropUSTRoot(attesterId, airdropLeaf);
        }
        // Create, hash, and insert a fresh state leaf
        StateLeaf memory stateLeaf = StateLeaf({
            identityCommitment: _identityCommitment,
            userStateRoot: defaultUserStateRoot
        });

        uint256 hashedLeaf = hashStateLeaf(stateLeaf);

        hasUserSignedUp[_identityCommitment] = true;
        numUserSignUps ++;

        emit Sequencer(currentEpoch, "NewGSTLeafInserted");
        emit UserSignUp(proofIndex, _identityCommitment, attesterId, airdropPosRep);
        emit NewGSTLeafInserted(currentEpoch, hashedLeaf, proofIndex);

        proofIndex ++;
    }

    /*
     * Verify if the attester has a valid signature as claimed
     * @param attester The address of user who wants to perform an action
     * @param siganture The signature signed by the attester
     */
    function verifySignature(address attester, bytes memory signature) internal view {
        // Attester signs over it's own address concatenated with this contract address
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(
                    abi.encodePacked(attester, this)
                )
            )
        );
        require(
            ECDSA.recover(messageHash, signature) == attester,
            "Unirep: invalid attester sign up signature"
        );
    }

    /*
     * Sign up an attester using the address who sends the transaction
     */
    function attesterSignUp() external {
        require(attesters[msg.sender] == 0, "Unirep: attester has already signed up");
        require(nextAttesterId < maxAttesters, "Unirep: maximum number of attester signups reached");

        attesters[msg.sender] = nextAttesterId;
        nextAttesterId ++;
    }

    /*
     * Sign up an attester using the claimed address and the signature
     * @param attester The address of the attester who wants to sign up
     * @param signature The signature of the attester
     */
    function attesterSignUpViaRelayer(address attester, bytes calldata signature) external {
        require(attesters[attester] == 0, "Unirep: attester has already signed up");
        require(nextAttesterId < maxAttesters, "Unirep: maximum number of attester signups reached");
        verifySignature(attester, signature);

        attesters[attester] = nextAttesterId;
        nextAttesterId ++;
    }

    /*
     * An attester can set the initial airdrop amount when user signs up through this attester
     * Then the contract inserts an airdropped leaf into the user's user state tree
     * @param _airdropAmount how much pos rep add to user's leaf
     */
    function setAirdropAmount(uint256 _airdropAmount) external {
        require(attesters[msg.sender] > 0, "Unirep: attester has not signed up yet");
        airdropAmount[msg.sender] = _airdropAmount;
    }

    /*
     * An attester submit the attestation with an epoch key proof
     * @param attestation The attestation that the attester wants to send to the epoch key
     * @param epochKeyProofData The epoch key and its epoch key proof and public signals 
     */
    function submitAttestation(Attestation calldata attestation, uint256 epochKey, uint256 _proofIndex) external payable {
        require(attesters[msg.sender] > 0, "Unirep: attester has not signed up yet");
        require(attesters[msg.sender] == attestation.attesterId, "Unirep: mismatched attesterId");
        require(msg.value == attestingFee, "Unirep: no attesting fee or incorrect amount");
        require(_proofIndex < proofIndex, "Unirep: invalid proof index");

        // Add to the cumulated attesting fee
        collectedAttestingFee = collectedAttestingFee.add(msg.value);

         // Process attestation
        emitAttestationEvent(msg.sender, attestation, epochKey, _proofIndex);
    }

    /*
     * An attester submit the attestation with an epoch key proof via a relayer
     * @param attester The address of the attester
     * @param signature The signature of the attester
     * @param attestation The attestation including positive reputation, negative reputation or graffiti
     * @param epochKeyProofData The epoch key proof and the public signals 
     */
    function submitAttestationViaRelayer(
        address attester,
        bytes calldata signature,
        Attestation calldata attestation,
        uint256 epochKey,
        uint256 _proofIndex
    ) external payable {
        verifySignature(attester, signature);
        require(attesters[attester] > 0, "Unirep: attester has not signed up yet");
        require(attesters[attester] == attestation.attesterId, "Unirep: mismatched attesterId");
        require(msg.value == attestingFee, "Unirep: no attesting fee or incorrect amount");
        require(_proofIndex < proofIndex, "Unirep: invalid proof index");

        // Add to the cumulated attesting fee
        collectedAttestingFee = collectedAttestingFee.add(msg.value);

        // Process attestation
        emitAttestationEvent(attester, attestation, epochKey, _proofIndex);
    }

    /*
     * A user should submit an epoch key proof and get a proof index
     * @param epochKeyProofData The epoch key proof and the public signals 
     */
    function submitEpochKeyProof(EpochKeyProofRelated memory epochKeyProofData) external {
        bytes32 proofNullifier = hashEpochKeyProof(epochKeyProofData);
        require(getProofIndex[proofNullifier] == 0, "Unirep: the proof has been submitted before");
        require(epochKeyProofData.epoch == currentEpoch, "Unirep: submit an epoch key proof with incorrect epoch");

        // emit proof event
        uint256 _proofIndex = proofIndex;
        emit EpochKeyProof(_proofIndex, currentEpoch, epochKeyProofData.epochKey, epochKeyProofData);
        getProofIndex[proofNullifier] = _proofIndex;
        proofIndex ++;
    }

    /*
     * An attester submit the airdrop attestation to an epoch key with a sign up proof
     * @param attestation The attestation that the attester wants to send to the epoch key
     * @param signUpProofData The epoch key and its proof and the public signals 
     */
    function airdropEpochKey(SignUpProofRelated memory signUpProofData) external payable {
        bytes32 proofNullifier = hashSignUpProof(signUpProofData);
        require(getProofIndex[proofNullifier] == 0, "Unirep: the proof has been submitted before");
        require(attesters[msg.sender] > 0, "Unirep: attester has not signed up yet");
        require(attesters[msg.sender] == signUpProofData.attesterId, "Unirep: mismatched attesterId");
        require(msg.value == attestingFee, "Unirep: no attesting fee or incorrect amount");
        require(signUpProofData.epoch == currentEpoch, "Unirep: submit an airdrop proof with incorrect epoch");

        // Add to the cumulated attesting fee
        collectedAttestingFee = collectedAttestingFee.add(msg.value);

        // attestation of airdrop
        Attestation memory attestation;
        attestation.attesterId = attesters[msg.sender];
        attestation.posRep = airdropAmount[msg.sender];
        attestation.signUp = 1;

        uint256 _proofIndex = proofIndex;
        // emit proof event
        emit UserSignedUpProof(_proofIndex, currentEpoch, signUpProofData.epochKey, signUpProofData);
        // Process attestation
        emitAttestationEvent(msg.sender, attestation, signUpProofData.epochKey, _proofIndex);
        getProofIndex[proofNullifier] = _proofIndex;
        proofIndex ++;
    }

    /*
     * A user spend reputation via an attester, the non-zero nullifiers will be processed as a negative attestation
     * @param _repNullifiers The reputation nullifiers that the user submitted to avoid double spending
     * @param _epochKey The epoch key of the user to receive negative attestation
     * @param _globalStateTree The global state tree root of the reputation proof
     * @param _minRep The minimum reputation that a user wants to prove that he has at least
     * @param _proveGraffiti The flag to indicate if the user wants to prove the pre-image of the graffiti
     * @param _graffitiPreImage The graffiti preimage that the user wants to prove
     * @param _proof The reputatiaon proof
     */
    function spendReputation(ReputationProofRelated memory reputationProofData) external payable {
        bytes32 proofNullifier = hashReputationProof(reputationProofData);
        require(getProofIndex[proofNullifier] == 0, "Unirep: the proof has been submitted before");
        require(attesters[msg.sender] > 0, "Unirep: attester has not signed up yet");
        require(attesters[msg.sender] == reputationProofData.attesterId, "Unirep: mismatched attesterId");
        require(msg.value == attestingFee, "Unirep: no attesting fee or incorrect amount");
        require(reputationProofData.repNullifiers.length == maxReputationBudget, "Unirep: invalid number of reputation nullifiers");
        require(reputationProofData.epoch == currentEpoch, "Unirep: submit a reputation proof with incorrect epoch");
        require(attesters[msg.sender] == reputationProofData.attesterId, "Unirep: incorrect attester ID in the reputation proof");

        // Add to the cumulated attesting fee
        collectedAttestingFee = collectedAttestingFee.add(msg.value);

        // attestation of spending reputation
        Attestation memory attestation;
        attestation.attesterId = attesters[msg.sender];
        attestation.negRep = reputationProofData.proveReputationAmount;

        uint256 _proofIndex = proofIndex;
        // emit proof event
        emit ReputationNullifierProof(
            _proofIndex, 
            currentEpoch,
            reputationProofData.epochKey,
            reputationProofData
        );
        // Process attestation
        emitAttestationEvent(msg.sender, attestation, reputationProofData.epochKey, _proofIndex);
        getProofIndex[proofNullifier] = _proofIndex;
        proofIndex ++;
    }

    function emitAttestationEvent(address attester, Attestation memory attestation, uint256 epochKey, uint256 _proofIndex) internal {

        // Validate attestation data
        require(attestation.posRep < SNARK_SCALAR_FIELD, "Unirep: invalid attestation posRep");
        require(attestation.negRep < SNARK_SCALAR_FIELD, "Unirep: invalid attestation negRep");
        require(attestation.graffiti < SNARK_SCALAR_FIELD, "Unirep: invalid attestation graffiti");
        require(attestation.signUp == 1 || attestation.signUp == 0, "Unirep: invalid attestation signUp");

        // Emit epoch key proof with attestation submitted event
        // And user can verify if the epoch key is valid or not
        emit Sequencer(currentEpoch, "AttestationSubmitted");
        emit AttestationSubmitted(
            currentEpoch,
            epochKey,
            attester,
            attestation,
            _proofIndex
        );
    }

    function beginEpochTransition() external {
        uint256 initGas = gasleft();

        require(block.timestamp - latestEpochTransitionTime >= epochLength, "Unirep: epoch not yet ended");

        // Mark epoch transitioned as complete and increase currentEpoch
        emit Sequencer(currentEpoch, "EpochEnded");
        emit EpochEnded(currentEpoch);

        latestEpochTransitionTime = block.timestamp;
        currentEpoch ++;

        uint256 gasUsed = initGas.sub(gasleft());
        epochTransitionCompensation[msg.sender] = epochTransitionCompensation[msg.sender].add(gasUsed.mul(tx.gasprice));
    }

    function startUserStateTransition(
        uint256 _blindedUserState,
        uint256 _blindedHashChain,
        uint256 _globalStateTree,
        uint256[8] calldata _proof
    ) external {
        bytes32 proofNullifier = hashStartTransitionProof(_blindedUserState, _blindedHashChain, _globalStateTree, _proof);
        require(getProofIndex[proofNullifier] == 0, "Unirep: the proof has been submitted before");
        
        uint256 _proofIndex = proofIndex;
        emit StartedTransitionProof(_proofIndex, _blindedUserState, _globalStateTree, _blindedHashChain, _proof);
        getProofIndex[proofNullifier] = _proofIndex;
        proofIndex ++;
    }

    function processAttestations(
        uint256 _outputBlindedUserState,
        uint256 _outputBlindedHashChain,
        uint256 _inputBlindedUserState,
        uint256[8] calldata _proof
    ) external {
        bytes32 proofNullifier = hashProcessAttestationsProof(_outputBlindedUserState, _outputBlindedHashChain, _inputBlindedUserState, _proof);
        require(getProofIndex[proofNullifier] == 0, "Unirep: the proof has been submitted before");

        uint256 _proofIndex = proofIndex;
        emit ProcessedAttestationsProof(_proofIndex, _inputBlindedUserState, _outputBlindedUserState, _outputBlindedHashChain, _proof);
        getProofIndex[proofNullifier] = _proofIndex;
        proofIndex ++;
    }

    function updateUserStateRoot(UserTransitionedRelated memory userTransitionedData, uint256[] memory proofIndexRecords) external {
        bytes32 proofNullifier = hashUserStateTransitionProof(userTransitionedData);
        require(getProofIndex[proofNullifier] == 0, "Unirep: the proof has been submitted before");
        // NOTE: this impl assumes all attestations are processed in a single snark.
        require(userTransitionedData.transitionFromEpoch < currentEpoch, "Can not transition from epoch that's greater or equal to current epoch");
        require(userTransitionedData.epkNullifiers.length == numEpochKeyNoncePerEpoch, "Unirep: invalid number of epk nullifiers");
        require(userTransitionedData.blindedUserStates.length == 2, "Unirep: invalid number of blinded user states");
        require(userTransitionedData.blindedHashChains.length == numEpochKeyNoncePerEpoch, "Unirep: invalid number of blinded hash chains");
        
        uint256 _proofIndex = proofIndex;
        emit Sequencer(currentEpoch, "NewGSTLeafInserted");
        emit UserStateTransitionProof(_proofIndex, userTransitionedData, proofIndexRecords);
        emit NewGSTLeafInserted(currentEpoch, userTransitionedData.newGlobalStateTreeLeaf, _proofIndex);

        getProofIndex[proofNullifier] = _proofIndex;
        proofIndex ++;
    }

    function verifyEpochKeyValidity(
        uint256 _globalStateTree,
        uint256 _epoch,
        uint256 _epochKey,
        uint256[8] calldata _proof) external view returns (bool) {
        // Before attesting to a given epoch key, an attester must verify validity of the epoch key:
        // 1. user has signed up
        // 2. nonce is no greater than numEpochKeyNoncePerEpoch
        // 3. user has transitioned to the epoch(by proving membership in the globalStateTree of that epoch)
        // 4. epoch key is correctly computed

        uint256[] memory _publicSignals = new uint256[](3);
        _publicSignals[0] = _globalStateTree;
        _publicSignals[1] = _epoch;
        _publicSignals[2] = _epochKey;

        // Ensure that each public input is within range of the snark scalar
        // field.
        // TODO: consider having more granular revert reasons
        for (uint8 i = 0; i < _publicSignals.length; i++) {
            require(
                _publicSignals[i] < SNARK_SCALAR_FIELD,
                "Unirep: each public signal must be lt the snark scalar field"
            );
        }

        ProofsRelated memory proof;
        // Unpack the snark proof
        (   
            proof.a,
            proof.b,
            proof.c
        ) = unpackProof(_proof);

        // Verify the proof
        proof.isValid = epkValidityVerifier.verifyProof(proof.a, proof.b, proof.c, _publicSignals);
        return proof.isValid;
    }

    function verifyStartTransitionProof(
        uint256 _blindedUserState,
        uint256 _blindedHashChain,
        uint256 _GSTRoot,
        uint256[8] calldata _proof) external view returns (bool) {

        uint256[] memory _publicSignals = new uint256[](4);
        _publicSignals[0] = _blindedUserState;
        _publicSignals[1] = _blindedHashChain;
        _publicSignals[2] = _GSTRoot;

        // Ensure that each public input is within range of the snark scalar
        // field.
        // TODO: consider having more granular revert reasons
        for (uint8 i = 0; i < _publicSignals.length; i++) {
            require(
                _publicSignals[i] < SNARK_SCALAR_FIELD,
                "Unirep: each public signal must be lt the snark scalar field"
            );
        }

        ProofsRelated memory proof;
        // Unpack the snark proof
        (   
            proof.a,
            proof.b,
            proof.c
        ) = unpackProof(_proof);

        // Verify the proof
        proof.isValid = startTransitionVerifier.verifyProof(proof.a, proof.b, proof.c, _publicSignals);
        return proof.isValid;
    }

    function verifyProcessAttestationProof(
        uint256 _outputBlindedUserState,
        uint256 _outputBlindedHashChain,
        uint256 _inputBlindedUserState,
        uint256[8] calldata _proof) external view returns (bool) {

        uint256[] memory _publicSignals = new uint256[](4);
        _publicSignals[0] = _outputBlindedUserState;
        _publicSignals[1] = _outputBlindedHashChain;
        _publicSignals[2] = _inputBlindedUserState;

        // Ensure that each public input is within range of the snark scalar
        // field.
        // TODO: consider having more granular revert reasons
        for (uint8 i = 0; i < _publicSignals.length; i++) {
            require(
                _publicSignals[i] < SNARK_SCALAR_FIELD,
                "Unirep: each public signal must be lt the snark scalar field"
            );
        }

        ProofsRelated memory proof;
        // Unpack the snark proof
        (   
            proof.a,
            proof.b,
            proof.c
        ) = unpackProof(_proof);

        // Verify the proof
        proof.isValid = processAttestationsVerifier.verifyProof(proof.a, proof.b, proof.c, _publicSignals);
        return proof.isValid;
    }

    function verifyUserStateTransition(
        uint256 _newGlobalStateTreeLeaf,
        uint256[] calldata _epkNullifiers,
        uint256 _transitionFromEpoch,
        uint256[] calldata _blindedUserStates,
        uint256 _fromGlobalStateTree,
        uint256[] calldata _blindedHashChains,
        uint256 _fromEpochTree,
        uint256[8] calldata _proof) external view returns (bool) {
        // Verify validity of new user state:
        // 1. User's identity and state exist in the provided global state tree
        // 2. Global state tree is updated correctly
        // 3. Attestations to each epoch key are processed and processed correctly
        // require(_epkNullifiers.length == numEpochKeyNoncePerEpoch, "Unirep: invalid number of epk nullifiers");

        uint256[] memory _publicSignals = new uint256[](6 + numEpochKeyNoncePerEpoch * 2);
        _publicSignals[0] = _newGlobalStateTreeLeaf;
        for (uint8 i = 0; i < numEpochKeyNoncePerEpoch; i++) {
            _publicSignals[i + 1] = _epkNullifiers[i];
        }
        _publicSignals[1 + numEpochKeyNoncePerEpoch] = _transitionFromEpoch;
        _publicSignals[2 + numEpochKeyNoncePerEpoch] = _blindedUserStates[0];
        _publicSignals[3 + numEpochKeyNoncePerEpoch] = _blindedUserStates[1];
        _publicSignals[4 + numEpochKeyNoncePerEpoch] = _fromGlobalStateTree;
        for (uint8 i = 0; i < numEpochKeyNoncePerEpoch; i++) {
            _publicSignals[5 + numEpochKeyNoncePerEpoch + i] = _blindedHashChains[i];
        }
        _publicSignals[5 + numEpochKeyNoncePerEpoch * 2] = _fromEpochTree;

        // Ensure that each public input is within range of the snark scalar
        // field.
        // TODO: consider having more granular revert reasons
        for (uint8 i = 0; i < _publicSignals.length; i++) {
            require(
                _publicSignals[i] < SNARK_SCALAR_FIELD,
                "Unirep: each public signal must be lt the snark scalar field"
            );
        }
        ProofsRelated memory proof;
        // Unpack the snark proof
        (   
            proof.a,
            proof.b,
            proof.c
        ) = unpackProof(_proof);

        // Verify the proof
        proof.isValid = userStateTransitionVerifier.verifyProof(proof.a, proof.b, proof.c, _publicSignals);
        return proof.isValid;
    }

    function verifyReputation(
        uint256[] calldata _repNullifiers,
        uint256 _epoch,
        uint256 _epochKey,
        uint256 _globalStateTree,
        uint256 _attesterId,
        uint256 _proveReputationAmount,
        uint256 _minRep,
        uint256 _proveGraffiti,
        uint256 _graffitiPreImage,
        uint256[8] calldata _proof) external view returns (bool) {
        // User prove his reputation by an attester:
        // 1. User exists in GST
        // 2. It is the latest state user transition to
        // 3. (optional) different reputation nullifiers equals to prove reputation amount
        // 4. (optional) (positive reputation - negative reputation) is greater than `_minRep`
        // 5. (optional) hash of graffiti pre-image matches
        uint256[] memory _publicSignals = new uint256[](18);
        for (uint8 i = 0; i < maxReputationBudget; i++) {
            _publicSignals[i] = _repNullifiers[i];
        }
        _publicSignals[maxReputationBudget] = _epoch;
        _publicSignals[maxReputationBudget + 1] = _epochKey;
        _publicSignals[maxReputationBudget + 2] = _globalStateTree;
        _publicSignals[maxReputationBudget + 3] = _attesterId;
        _publicSignals[maxReputationBudget + 4] = _proveReputationAmount;
        _publicSignals[maxReputationBudget + 5] = _minRep;
        _publicSignals[maxReputationBudget + 6] = _proveGraffiti;
        _publicSignals[maxReputationBudget + 7] = _graffitiPreImage;

        // Ensure that each public input is within range of the snark scalar
        // field.
        // TODO: consider having more granular revert reasons
        for (uint8 i = 0; i < _publicSignals.length; i++) {
            require(
                _publicSignals[i] < SNARK_SCALAR_FIELD,
                "Unirep: each public signal must be lt the snark scalar field"
            );
        }

        ProofsRelated memory proof;
        // Unpack the snark proof
        (   
            proof.a,
            proof.b,
            proof.c
        ) = unpackProof(_proof);

        // Verify the proof
        proof.isValid = reputationVerifier.verifyProof(proof.a, proof.b, proof.c, _publicSignals);
        return proof.isValid;
    }

    function verifyUserSignUp(
        uint256 _epoch,
        uint256 _epochKey,
        uint256 _globalStateTree,
        uint256 _attesterId,
        uint256[8] calldata _proof) external view returns (bool) {
        // User prove his reputation by an attester:
        // 1. User exists in GST
        // 2. It is the latest state user transition to
        // 3. User has a signUp flag in the attester's leaf
        uint256[] memory _publicSignals = new uint256[](4);
        _publicSignals[0] = _epoch;
        _publicSignals[1] = _epochKey;
        _publicSignals[2] = _globalStateTree;
        _publicSignals[3] = _attesterId;

        // Ensure that each public input is within range of the snark scalar
        // field.
        // TODO: consider having more granular revert reasons
        for (uint8 i = 0; i < _publicSignals.length; i++) {
            require(
                _publicSignals[i] < SNARK_SCALAR_FIELD,
                "Unirep: each public signal must be lt the snark scalar field"
            );
        }

        ProofsRelated memory proof;
        // Unpack the snark proof
        (   
            proof.a,
            proof.b,
            proof.c
        ) = unpackProof(_proof);

        // Verify the proof
        proof.isValid = userSignUpVerifier.verifyProof(proof.a, proof.b, proof.c, _publicSignals);
        return proof.isValid;
    }

    function min(uint a, uint b) internal pure returns (uint) {
        if (a > b) {
            return b;
        } else {
            return a;
        }
    }

    /*
     * A helper function to convert an array of 8 uint256 values into the a, b,
     * and c array values that the zk-SNARK verifier's verifyProof accepts.
     */
    function unpackProof(
        uint256[8] memory _proof
    ) public pure returns (
        uint256[2] memory,
        uint256[2][2] memory,
        uint256[2] memory
    ) {

        return (
            [_proof[0], _proof[1]],
            [
                [_proof[2], _proof[3]],
                [_proof[4], _proof[5]]
            ],
            [_proof[6], _proof[7]]
        );
    }

    function hashedBlankStateLeaf() public view returns (uint256) {
        StateLeaf memory stateLeaf = StateLeaf({
            identityCommitment: 0,
            userStateRoot: emptyUserStateRoot
        });

        return hashStateLeaf(stateLeaf);
    }

    function calcAirdropUSTRoot(uint256 _leafIndex, uint256 _leafValue) public view returns (uint256) {
        uint256[5] memory defaultStateLeafValues;
        for (uint8 i = 0; i < 5; i++) {
            defaultStateLeafValues[i] = 0;
        }
        uint256 defaultUserStateLeaf = hash5(defaultStateLeafValues);
        return computeOneNonZeroLeafRoot(treeDepths.userStateTreeDepth, _leafIndex, _leafValue, defaultUserStateLeaf);
    }

    function calcEmptyUserStateTreeRoot(uint8 _levels) internal pure returns (uint256) {
        uint256[5] memory defaultStateLeafValues;
        for (uint8 i = 0; i < 5; i++) {
            defaultStateLeafValues[i] = 0;
        }
        uint256 defaultUserStateLeaf = hash5(defaultStateLeafValues);
        return computeEmptyRoot(_levels, defaultUserStateLeaf);
    }

    function calcEmptyGlobalStateTreeRoot(uint8 _levels) internal view returns (uint256) {
        // Compute the hash of a blank state leaf
        StateLeaf memory stateLeaf = StateLeaf({
            identityCommitment: 0,
            userStateRoot: emptyUserStateRoot
        });

        uint256 h = hashStateLeaf(stateLeaf);

        return computeEmptyRoot(_levels, h);
    }

    /*
     * Functions to burn fee and collect compenstation.
     */
    function burnAttestingFee() external {
        uint256 amount = collectedAttestingFee;
        collectedAttestingFee = 0;
        Address.sendValue(payable(address(0)), amount);
    }

    function collectEpochTransitionCompensation() external {
        // NOTE: currently there are no revenue to pay for epoch transition compensation
        uint256 amount = epochTransitionCompensation[msg.sender];
        epochTransitionCompensation[msg.sender] = 0;
        Address.sendValue(payable(msg.sender), amount);
    }
}