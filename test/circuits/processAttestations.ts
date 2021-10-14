import * as path from 'path'
import { expect } from "chai"
import { genRandomSalt, hash5, hashLeftRight, SnarkBigInt, genIdentity, SparseMerkleTreeImpl, stringifyBigInts } from "../../crypto"
import { compileAndLoadCircuit, executeCircuit, getSignalByName, genProofAndPublicSignals, verifyProof } from "../../circuits/utils"
import { Attestation, Reputation } from '../../core'
import { numAttestationsPerProof } from "../../config/testLocal"
import { genNewUserStateTree } from '../utils'

describe('Process attestation circuit', function () {
    this.timeout(300000)

    let circuit

    const epoch = BigInt(1)
    const nonce = BigInt(0)
    const toNonce = BigInt(1)
    const user = genIdentity()
    const signUp = 1

    let userStateTree: SparseMerkleTreeImpl
    let intermediateUserStateTreeRoots, userStateTreePathElements, noAttestationUserStateTreePathElements
    let oldPosReps, oldNegReps, oldGraffities, oldSignUps
    let hashChainStarter = genRandomSalt()
    let inputBlindedUserState

    let reputationRecords: { [key: string]: Reputation } = {}
    let attesterIds: BigInt[], posReps: BigInt[], negReps: BigInt[], graffities: SnarkBigInt[], signUps: BigInt[], overwriteGraffitis: BigInt[]
    let selectors: number[] = []
    let hashChainResult: SnarkBigInt

    before(async () => {
        const startCompileTime = Math.floor(new Date().getTime() / 1000)
        const circuitPath = path.join(__dirname, '../../circuits/test/processAttestations_test.circom')
        circuit = await compileAndLoadCircuit(circuitPath)
        const endCompileTime = Math.floor(new Date().getTime() / 1000)
        console.log(`Compile time: ${endCompileTime - startCompileTime} seconds`)

        attesterIds = []
        posReps = []
        negReps = []
        graffities = []
        signUps = []
        overwriteGraffitis = []

        // User state
        userStateTree = await genNewUserStateTree()
        intermediateUserStateTreeRoots = []
        userStateTreePathElements = []
        noAttestationUserStateTreePathElements = []  // User merkle proof of leaf 0 if no attestation to process
        oldPosReps = []
        oldNegReps = []
        oldGraffities = []
        oldSignUps = []

        // Bootstrap user state
        for (let i = 0; i < numAttestationsPerProof; i++) {
            const  attesterId = BigInt(i + 1)
            if (reputationRecords[attesterId.toString()] === undefined) {
                reputationRecords[attesterId.toString()] = new Reputation(
                    BigInt(Math.floor(Math.random() * 100)),
                    BigInt(Math.floor(Math.random() * 100)),
                    genRandomSalt(),
                    BigInt(signUp)
                )
            }
            await userStateTree.update(attesterId, reputationRecords[attesterId.toString()].hash())
        }
        intermediateUserStateTreeRoots.push(userStateTree.getRootHash())
        const leafZeroPathElements = await userStateTree.getMerkleProof(BigInt(0))
        for (let i = 0; i < numAttestationsPerProof; i++) noAttestationUserStateTreePathElements.push(leafZeroPathElements)

        // Ensure as least one of the selectors is true
        const selTrue = Math.floor(Math.random() * numAttestationsPerProof)
        for (let i = 0; i < numAttestationsPerProof; i++) {
            if (i == selTrue) selectors.push(1)
            else selectors.push(Math.floor(Math.random() * 2))
        }

        hashChainResult = hashChainStarter
        for (let i = 0; i < numAttestationsPerProof; i++) {
            const attesterId = BigInt(i + 1)
            const attestation: Attestation = new Attestation(
                attesterId,
                BigInt(Math.floor(Math.random() * 100)),
                BigInt(Math.floor(Math.random() * 100)),
                BigInt(0),
                BigInt(signUp),
            )
            attesterIds.push(attesterId)
            posReps.push(attestation['posRep'])
            negReps.push(attestation['negRep'])
            graffities.push(attestation['graffiti'])
            signUps.push(attestation['signUp'])
            overwriteGraffitis.push(BigInt(attestation['graffiti'] != BigInt(0)))

            oldPosReps.push(reputationRecords[attesterId.toString()]['posRep'])
            oldNegReps.push(reputationRecords[attesterId.toString()]['negRep'])
            oldGraffities.push(reputationRecords[attesterId.toString()]['graffiti'])
            oldSignUps.push(reputationRecords[attesterId.toString()]['signUp'])

            if (selectors[i] == 1) {
                // Get old reputation record proof
                const oldReputationRecordProof = await userStateTree.getMerkleProof(attesterId)
                userStateTreePathElements.push(oldReputationRecordProof)

                // Update reputation record
                reputationRecords[attesterId.toString()].update(
                    attestation['posRep'],
                    attestation['negRep'],
                    attestation['graffiti'],
                    attestation['signUp']
                )

                await userStateTree.update(attesterId, reputationRecords[attesterId.toString()].hash())

                const attestation_hash = attestation.hash()
                hashChainResult = hashLeftRight(attestation_hash, hashChainResult)
            } else {
                const leafZeroPathElements = await userStateTree.getMerkleProof(BigInt(0))
                userStateTreePathElements.push(leafZeroPathElements)
            }
            
            intermediateUserStateTreeRoots.push(userStateTree.getRootHash())
        }
        inputBlindedUserState = hash5([user['identityNullifier'], intermediateUserStateTreeRoots[0], epoch, nonce])
    })

    it('successfully process attestations', async () => {
        const circuitInputs = {
            epoch: epoch,
            from_nonce: nonce,
            to_nonce: nonce,
            identity_nullifier: user['identityNullifier'],
            intermediate_user_state_tree_roots: intermediateUserStateTreeRoots,
            old_pos_reps: oldPosReps,
            old_neg_reps: oldNegReps,
            old_graffities: oldGraffities,
            old_sign_ups: oldSignUps,
            path_elements: userStateTreePathElements,
            attester_ids: attesterIds,
            pos_reps: posReps,
            neg_reps: negReps,
            graffities: graffities,
            overwrite_graffities: overwriteGraffitis,
            sign_ups: signUps,
            selectors: selectors,
            hash_chain_starter: hashChainStarter,
            input_blinded_user_state: inputBlindedUserState,
        }
        const witness = await executeCircuit(circuit, circuitInputs)
        const outputUserState = getSignalByName(circuit, witness, 'main.blinded_user_state')
        const expectedUserState = hash5([user['identityNullifier'], intermediateUserStateTreeRoots[numAttestationsPerProof], epoch, nonce])
        expect(outputUserState).to.equal(expectedUserState)
        inputBlindedUserState = outputUserState

        const outputHashChainResult = getSignalByName(circuit, witness, 'main.blinded_hash_chain_result')
        const expectedHashChainResult = hash5([user['identityNullifier'], hashChainResult, epoch, nonce])
        expect(outputHashChainResult).to.equal(expectedHashChainResult)

        const startTime = new Date().getTime()
        const results = await genProofAndPublicSignals('processAttestations', stringifyBigInts(circuitInputs))
        const endTime = new Date().getTime()
        console.log(`Gen Proof time: ${endTime - startTime} ms (${Math.floor((endTime - startTime) / 1000)} s)`)
        const isValid = await verifyProof('processAttestations', results['proof'], results['publicSignals'])
        expect(isValid).to.be.true
    })

    it('successfully process zero attestations', async () => {
        const zeroSelectors = selectors.map(() => 0)
        const noAttestationHashChainResult = hashChainStarter
        const initialUserStateTreeRoot = intermediateUserStateTreeRoots[0]
        const noAttestationIntermediateUserStateTreeRoots = intermediateUserStateTreeRoots.map(() => initialUserStateTreeRoot)
        const zeroInputUserState = hash5([user['identityNullifier'], initialUserStateTreeRoot, epoch, nonce])
        const circuitInputs = {
            epoch: epoch,
            from_nonce: nonce,
            to_nonce: nonce,
            identity_nullifier: user['identityNullifier'],
            intermediate_user_state_tree_roots: noAttestationIntermediateUserStateTreeRoots,
            old_pos_reps: oldPosReps,
            old_neg_reps: oldNegReps,
            old_graffities: oldGraffities,
            old_sign_ups: oldSignUps,
            path_elements: noAttestationUserStateTreePathElements,
            attester_ids: attesterIds,
            pos_reps: posReps,
            neg_reps: negReps,
            graffities: graffities,
            overwrite_graffities: overwriteGraffitis,
            sign_ups: signUps,
            selectors: zeroSelectors,
            hash_chain_starter: hashChainStarter,
            input_blinded_user_state: zeroInputUserState,
        }

        const witness = await executeCircuit(circuit, circuitInputs)
        const outputUserState = getSignalByName(circuit, witness, 'main.blinded_user_state')
        const expectedUserState = hash5([user['identityNullifier'], noAttestationIntermediateUserStateTreeRoots[numAttestationsPerProof], epoch, nonce])
        expect(outputUserState).to.equal(expectedUserState)

        const outputHashChainResult = getSignalByName(circuit, witness, 'main.blinded_hash_chain_result')
        const expectedHashChainResult = hash5([user['identityNullifier'], noAttestationHashChainResult, epoch, nonce])
        expect(outputHashChainResult).to.equal(expectedHashChainResult)
    })

    it('successfully continue to process attestations', async () => {
        hashChainStarter = hashChainResult

        oldPosReps = []
        oldNegReps = []
        oldGraffities = []
        oldSignUps = []
        attesterIds = []
        posReps = []
        negReps = []
        graffities = []
        overwriteGraffitis = []
        signUps = []
        selectors = []

        intermediateUserStateTreeRoots = []
        userStateTreePathElements = []
        intermediateUserStateTreeRoots.push(userStateTree.getRootHash())

        // Ensure as least one of the selectors is true
        const selTrue = Math.floor(Math.random() * numAttestationsPerProof)
        for (let i = 0; i < numAttestationsPerProof; i++) {
            if (i == selTrue) selectors.push(1)
            else selectors.push(Math.floor(Math.random() * 2))
        }

        for (let i = 0; i < numAttestationsPerProof; i++) {
            const attesterId = BigInt(i + 1)
            const attestation: Attestation = new Attestation(
                attesterId,
                BigInt(Math.floor(Math.random() * 100)),
                BigInt(Math.floor(Math.random() * 100)),
                genRandomSalt(),
                BigInt(signUp)
            )
            attesterIds.push(attesterId)
            posReps.push(attestation['posRep'])
            negReps.push(attestation['negRep'])
            graffities.push(attestation['graffiti'])
            overwriteGraffitis.push(BigInt(attestation['graffiti'] != BigInt(0)))
            signUps.push(attestation['signUp'])
            
            if (selectors[i] == 1) {
                // Get old reputation record
                oldPosReps.push(reputationRecords[attesterId.toString()].posRep)
                oldNegReps.push(reputationRecords[attesterId.toString()].negRep)
                oldGraffities.push(reputationRecords[attesterId.toString()].graffiti)
                oldSignUps.push(reputationRecords[attesterId.toString()].signUp)

                // Get old reputation record proof
                const oldReputationRecordProof = await userStateTree.getMerkleProof(attesterId)
                userStateTreePathElements.push(oldReputationRecordProof)

                // Update reputation record
                reputationRecords[attesterId.toString()].update(
                    attestation['posRep'],
                    attestation['negRep'],
                    attestation['graffiti'],
                    attestation['signUp']
                )

                await userStateTree.update(attesterId, reputationRecords[attesterId.toString()].hash())

                const attestation_hash = attestation.hash()
                hashChainResult = hashLeftRight(attestation_hash, hashChainResult)
            } else {
                oldPosReps.push(BigInt(0))
                oldNegReps.push(BigInt(0))
                oldGraffities.push(BigInt(0))
                oldSignUps.push(BigInt(0))

                const leafZeroPathElements = await userStateTree.getMerkleProof(BigInt(0))
                userStateTreePathElements.push(leafZeroPathElements)
            }
            
            intermediateUserStateTreeRoots.push(userStateTree.getRootHash())
        }

        const circuitInputs = {
            epoch: epoch,
            from_nonce: nonce,
            to_nonce: nonce,
            identity_nullifier: user['identityNullifier'],
            intermediate_user_state_tree_roots: intermediateUserStateTreeRoots,
            old_pos_reps: oldPosReps,
            old_neg_reps: oldNegReps,
            old_graffities: oldGraffities,
            old_sign_ups: oldSignUps,
            path_elements: userStateTreePathElements,
            attester_ids: attesterIds,
            pos_reps: posReps,
            neg_reps: negReps,
            graffities: graffities,
            overwrite_graffities: overwriteGraffitis,
            sign_ups: signUps,
            selectors: selectors,
            hash_chain_starter: hashChainStarter,
            input_blinded_user_state: inputBlindedUserState,
        }
        const witness = await executeCircuit(circuit, circuitInputs)
        const outputUserState = getSignalByName(circuit, witness, 'main.blinded_user_state')
        const expectedUserState = hash5([user['identityNullifier'], intermediateUserStateTreeRoots[numAttestationsPerProof], epoch, nonce])
        expect(outputUserState).to.equal(expectedUserState)
        inputBlindedUserState = outputUserState

        const outputHashChainResult = getSignalByName(circuit, witness, 'main.blinded_hash_chain_result')
        const expectedHashChainResult = hash5([user['identityNullifier'], hashChainResult, epoch, nonce])
        expect(outputHashChainResult).to.equal(expectedHashChainResult)
    })

    it('successfully continue to process attestations to next epoch key', async () => {
        hashChainStarter = hashChainResult

        oldPosReps = []
        oldNegReps = []
        oldGraffities = []
        oldSignUps = []
        attesterIds = []
        posReps = []
        negReps = []
        graffities = []
        overwriteGraffitis = []
        signUps = []
        selectors = []

        intermediateUserStateTreeRoots = []
        userStateTreePathElements = []
        intermediateUserStateTreeRoots.push(userStateTree.getRootHash())

        // Ensure as least one of the selectors is true
        const selTrue = Math.floor(Math.random() * numAttestationsPerProof)
        for (let i = 0; i < numAttestationsPerProof; i++) {
            if (i == selTrue) selectors.push(1)
            else selectors.push(Math.floor(Math.random() * 2))
        }

        for (let i = 0; i < numAttestationsPerProof; i++) {
            const attesterId = BigInt(i + 1)
            const attestation: Attestation = new Attestation(
                attesterId,
                BigInt(Math.floor(Math.random() * 100)),
                BigInt(Math.floor(Math.random() * 100)),
                genRandomSalt(),
                BigInt(signUp)
            )
            attesterIds.push(attesterId)
            posReps.push(attestation['posRep'])
            negReps.push(attestation['negRep'])
            graffities.push(attestation['graffiti'])
            overwriteGraffitis.push(BigInt(attestation['graffiti'] != BigInt(0)))
            signUps.push(attestation['signUp'])
            
            if (selectors[i] == 1) {
                // Get old reputation record
                oldPosReps.push(reputationRecords[attesterId.toString()].posRep)
                oldNegReps.push(reputationRecords[attesterId.toString()].negRep)
                oldGraffities.push(reputationRecords[attesterId.toString()].graffiti)
                oldSignUps.push(reputationRecords[attesterId.toString()].signUp)

                // Get old reputation record proof
                const oldReputationRecordProof = await userStateTree.getMerkleProof(attesterId)
                userStateTreePathElements.push(oldReputationRecordProof)

                // Update reputation record
                reputationRecords[attesterId.toString()].update(
                    attestation['posRep'],
                    attestation['negRep'],
                    attestation['graffiti'],
                    attestation['signUp']
                )

                await userStateTree.update(attesterId, reputationRecords[attesterId.toString()].hash())

                const attestation_hash = attestation.hash()
                hashChainResult = hashLeftRight(attestation_hash, hashChainResult)
            } else {
                oldPosReps.push(BigInt(0))
                oldNegReps.push(BigInt(0))
                oldGraffities.push(BigInt(0))
                oldSignUps.push(BigInt(0))

                const leafZeroPathElements = await userStateTree.getMerkleProof(BigInt(0))
                userStateTreePathElements.push(leafZeroPathElements)
            }
            
            intermediateUserStateTreeRoots.push(userStateTree.getRootHash())
        }

        const circuitInputs = {
            epoch: epoch,
            from_nonce: nonce,
            to_nonce: toNonce,
            identity_nullifier: user['identityNullifier'],
            intermediate_user_state_tree_roots: intermediateUserStateTreeRoots,
            old_pos_reps: oldPosReps,
            old_neg_reps: oldNegReps,
            old_graffities: oldGraffities,
            old_sign_ups: oldSignUps,
            path_elements: userStateTreePathElements,
            attester_ids: attesterIds,
            pos_reps: posReps,
            neg_reps: negReps,
            graffities: graffities,
            overwrite_graffities: overwriteGraffitis,
            sign_ups: signUps,
            selectors: selectors,
            hash_chain_starter: hashChainStarter,
            input_blinded_user_state: inputBlindedUserState,
        }
        const witness = await executeCircuit(circuit, circuitInputs)
        const outputUserState = getSignalByName(circuit, witness, 'main.blinded_user_state')
        const expectedUserState = hash5([user['identityNullifier'], intermediateUserStateTreeRoots[numAttestationsPerProof], epoch, toNonce])
        expect(outputUserState).to.equal(expectedUserState)
        inputBlindedUserState = outputUserState

        const outputHashChainResult = getSignalByName(circuit, witness, 'main.blinded_hash_chain_result')
        const expectedHashChainResult = hash5([user['identityNullifier'], hashChainResult, epoch, toNonce])
        expect(outputHashChainResult).to.equal(expectedHashChainResult)
    })

    it('Same attester give reputation to same epoch keys should work', async () => {
        hashChainStarter = hashChainResult

        oldPosReps = []
        oldNegReps = []
        oldGraffities = []
        oldSignUps = []
        attesterIds = []
        posReps = []
        negReps = []
        graffities = []
        overwriteGraffitis = []
        signUps = []
        selectors = []

        intermediateUserStateTreeRoots = []
        userStateTreePathElements = []
        intermediateUserStateTreeRoots.push(userStateTree.getRootHash())

        // Ensure as least one of the selectors is true
        const selTrue = Math.floor(Math.random() * numAttestationsPerProof)
        for (let i = 0; i < numAttestationsPerProof; i++) {
            if (i == selTrue) selectors.push(1)
            else selectors.push(Math.floor(Math.random() * 2))
        }

        for (let i = 0; i < numAttestationsPerProof; i++) {
            const attesterId = BigInt(i + 1)
            const attestation: Attestation = new Attestation(
                attesterId,
                BigInt(Math.floor(Math.random() * 100)),
                BigInt(Math.floor(Math.random() * 100)),
                genRandomSalt(),
                BigInt(signUp)
            )
            attesterIds.push(attesterId)
            posReps.push(attestation['posRep'])
            negReps.push(attestation['negRep'])
            graffities.push(attestation['graffiti'])
            overwriteGraffitis.push(BigInt(attestation['graffiti'] != BigInt(0)))
            signUps.push(attestation['signUp'])
            
            if (selectors[i] == 1) {
                // Get old reputation record
                oldPosReps.push(reputationRecords[attesterId.toString()].posRep)
                oldNegReps.push(reputationRecords[attesterId.toString()].negRep)
                oldGraffities.push(reputationRecords[attesterId.toString()].graffiti)
                oldSignUps.push(reputationRecords[attesterId.toString()].signUp)

                // Get old reputation record proof
                const oldReputationRecordProof = await userStateTree.getMerkleProof(attesterId)
                userStateTreePathElements.push(oldReputationRecordProof)

                // Update reputation record
                reputationRecords[attesterId.toString()].update(
                    attestation['posRep'],
                    attestation['negRep'],
                    attestation['graffiti'],
                    attestation['signUp']
                )

                await userStateTree.update(attesterId, reputationRecords[attesterId.toString()].hash())

                const attestation_hash = attestation.hash()
                hashChainResult = hashLeftRight(attestation_hash, hashChainResult)
            } else {
                oldPosReps.push(BigInt(0))
                oldNegReps.push(BigInt(0))
                oldGraffities.push(BigInt(0))
                oldSignUps.push(BigInt(0))
                
                const leafZeroPathElements = await userStateTree.getMerkleProof(BigInt(0))
                userStateTreePathElements.push(leafZeroPathElements)
            }
            
            intermediateUserStateTreeRoots.push(userStateTree.getRootHash())
        }

        const circuitInputs = {
            epoch: epoch,
            from_nonce: toNonce,
            to_nonce: toNonce,
            identity_nullifier: user['identityNullifier'],
            intermediate_user_state_tree_roots: intermediateUserStateTreeRoots,
            old_pos_reps: oldPosReps,
            old_neg_reps: oldNegReps,
            old_graffities: oldGraffities,
            old_sign_ups: oldSignUps,
            path_elements: userStateTreePathElements,
            attester_ids: attesterIds,
            pos_reps: posReps,
            neg_reps: negReps,
            graffities: graffities,
            overwrite_graffities: overwriteGraffitis,
            sign_ups: signUps,
            selectors: selectors,
            hash_chain_starter: hashChainStarter,
            input_blinded_user_state: inputBlindedUserState,
        }
        const witness = await executeCircuit(circuit, circuitInputs)
        const outputUserState = getSignalByName(circuit, witness, 'main.blinded_user_state')
        const expectedUserState = hash5([user['identityNullifier'], intermediateUserStateTreeRoots[numAttestationsPerProof], epoch, toNonce])
        expect(outputUserState).to.equal(expectedUserState)
        inputBlindedUserState = outputUserState

        const outputHashChainResult = getSignalByName(circuit, witness, 'main.blinded_hash_chain_result')
        const expectedHashChainResult = hash5([user['identityNullifier'], hashChainResult, epoch, toNonce])
        expect(outputHashChainResult).to.equal(expectedHashChainResult)
    })

    it('Sign up flag should not be overwritten', async () => {
        hashChainStarter = hashChainResult

        oldPosReps = []
        oldNegReps = []
        oldGraffities = []
        oldSignUps = []
        attesterIds = []
        posReps = []
        negReps = []
        graffities = []
        overwriteGraffitis = []
        signUps = []
        selectors = []

        intermediateUserStateTreeRoots = []
        userStateTreePathElements = []
        intermediateUserStateTreeRoots.push(userStateTree.getRootHash())

        const notSignUp = 0

        // Ensure as least one of the selectors is true
        const selTrue = Math.floor(Math.random() * numAttestationsPerProof)
        for (let i = 0; i < numAttestationsPerProof; i++) {
            if (i == selTrue) selectors.push(1)
            else selectors.push(Math.floor(Math.random() * 2))
        }

        for (let i = 0; i < numAttestationsPerProof; i++) {
            const attesterId = BigInt(i + 1)
            const attestation: Attestation = new Attestation(
                attesterId,
                BigInt(Math.floor(Math.random() * 100)),
                BigInt(Math.floor(Math.random() * 100)),
                genRandomSalt(),
                BigInt(notSignUp)
            )
            attesterIds.push(attesterId)
            posReps.push(attestation['posRep'])
            negReps.push(attestation['negRep'])
            graffities.push(attestation['graffiti'])
            overwriteGraffitis.push(BigInt(attestation['graffiti'] != BigInt(0)))
            signUps.push(attestation['signUp'])
            
            if (selectors[i] == 1) {
                // Get old reputation record
                oldPosReps.push(reputationRecords[attesterId.toString()].posRep)
                oldNegReps.push(reputationRecords[attesterId.toString()].negRep)
                oldGraffities.push(reputationRecords[attesterId.toString()].graffiti)
                oldSignUps.push(reputationRecords[attesterId.toString()].signUp)

                // Get old reputation record proof
                const oldReputationRecordProof = await userStateTree.getMerkleProof(attesterId)
                userStateTreePathElements.push(oldReputationRecordProof)

                // Update reputation record
                reputationRecords[attesterId.toString()].update(
                    attestation['posRep'],
                    attestation['negRep'],
                    attestation['graffiti'],
                    attestation['signUp']
                )

                await userStateTree.update(attesterId, reputationRecords[attesterId.toString()].hash())

                const attestation_hash = attestation.hash()
                hashChainResult = hashLeftRight(attestation_hash, hashChainResult)
            } else {
                oldPosReps.push(BigInt(0))
                oldNegReps.push(BigInt(0))
                oldGraffities.push(BigInt(0))
                oldSignUps.push(BigInt(0))
                
                const leafZeroPathElements = await userStateTree.getMerkleProof(BigInt(0))
                userStateTreePathElements.push(leafZeroPathElements)
            }
            
            intermediateUserStateTreeRoots.push(userStateTree.getRootHash())
        }

        const circuitInputs = {
            epoch: epoch,
            from_nonce: toNonce,
            to_nonce: toNonce,
            identity_nullifier: user['identityNullifier'],
            intermediate_user_state_tree_roots: intermediateUserStateTreeRoots,
            old_pos_reps: oldPosReps,
            old_neg_reps: oldNegReps,
            old_graffities: oldGraffities,
            old_sign_ups: oldSignUps,
            path_elements: userStateTreePathElements,
            attester_ids: attesterIds,
            pos_reps: posReps,
            neg_reps: negReps,
            graffities: graffities,
            overwrite_graffities: overwriteGraffitis,
            sign_ups: signUps,
            selectors: selectors,
            hash_chain_starter: hashChainStarter,
            input_blinded_user_state: inputBlindedUserState,
        }
        const witness = await executeCircuit(circuit, circuitInputs)
        const outputUserState = getSignalByName(circuit, witness, 'main.blinded_user_state')
        const expectedUserState = hash5([user['identityNullifier'], intermediateUserStateTreeRoots[numAttestationsPerProof], epoch, toNonce])
        expect(outputUserState).to.equal(expectedUserState)

        const outputHashChainResult = getSignalByName(circuit, witness, 'main.blinded_hash_chain_result')
        const expectedHashChainResult = hash5([user['identityNullifier'], hashChainResult, epoch, toNonce])
        expect(outputHashChainResult).to.equal(expectedHashChainResult)
    })

    it('process attestations with wrong attestation record should not work', async () => {
        let indexWrongAttestationRecord = Math.floor(Math.random() * numAttestationsPerProof)
        while (selectors[indexWrongAttestationRecord] == 0) indexWrongAttestationRecord = (indexWrongAttestationRecord + 1) % numAttestationsPerProof
        const wrongOldPosReps = oldPosReps.slice()
        wrongOldPosReps[indexWrongAttestationRecord] = BigInt(Math.floor(Math.random() * 100))
        const wrongOldNegReps = oldNegReps.slice()
        wrongOldNegReps[indexWrongAttestationRecord] = BigInt(Math.floor(Math.random() * 100))
        const wrongOldGraffities = oldGraffities.slice()
        wrongOldGraffities[indexWrongAttestationRecord] = genRandomSalt()
        const circuitInputs = {
            epoch: epoch,
            from_nonce: toNonce,
            to_nonce: toNonce,
            identity_nullifier: user['identityNullifier'],
            intermediate_user_state_tree_roots: intermediateUserStateTreeRoots,
            old_pos_reps: wrongOldPosReps,
            old_neg_reps: wrongOldNegReps,
            old_graffities: wrongOldGraffities,
            old_sign_ups: oldSignUps,
            path_elements: userStateTreePathElements,
            attester_ids: attesterIds,
            pos_reps: posReps,
            neg_reps: negReps,
            graffities: graffities,
            overwrite_graffities: overwriteGraffitis,
            sign_ups: signUps,
            selectors: selectors,
            hash_chain_starter: hashChainStarter,
            input_blinded_user_state: inputBlindedUserState,
        }

        let error
        try {
            await executeCircuit(circuit, circuitInputs)
        } catch (e) {
            error = e
            expect(true).to.be.true
        } finally {
            if (!error) throw Error("Root mismatch results from wrong attestation record should throw error")
        }
    })

    it('process attestations with wrong intermediate roots should not work', async () => {
        const wrongIntermediateUserStateTreeRoots = intermediateUserStateTreeRoots.slice()
        const indexWrongRoot = Math.floor(Math.random() * numAttestationsPerProof)
        wrongIntermediateUserStateTreeRoots[indexWrongRoot] = genRandomSalt()
        const circuitInputs = {
            epoch: epoch,
            from_nonce: toNonce,
            to_nonce: toNonce,
            identity_nullifier: user['identityNullifier'],
            intermediate_user_state_tree_roots: wrongIntermediateUserStateTreeRoots,
            old_pos_reps: oldPosReps,
            old_neg_reps: oldNegReps,
            old_graffities: oldGraffities,
            old_sign_ups: oldSignUps,
            path_elements: userStateTreePathElements,
            attester_ids: attesterIds,
            pos_reps: posReps,
            neg_reps: negReps,
            graffities: graffities,
            overwrite_graffities: overwriteGraffitis,
            sign_ups: signUps,
            selectors: selectors,
            hash_chain_starter: hashChainStarter,
            input_blinded_user_state: inputBlindedUserState,
        }

        let error
        try {
            await executeCircuit(circuit, circuitInputs)
        } catch (e) {
            error = e
            expect(true).to.be.true
        } finally {
            if (!error) throw Error("Root mismatch results from wrong intermediate roots should throw error")
        }
    })

    it('process attestations with wrong path elements should not work', async () => {
        const indexWrongPathElements = Math.floor(Math.random() * numAttestationsPerProof)
        userStateTreePathElements[indexWrongPathElements].reverse()
        const circuitInputs = {
            epoch: epoch,
            from_nonce: toNonce,
            to_nonce: toNonce,
            identity_nullifier: user['identityNullifier'],
            intermediate_user_state_tree_roots: intermediateUserStateTreeRoots,
            old_pos_reps: oldPosReps,
            old_neg_reps: oldNegReps,
            old_graffities: oldGraffities,
            old_sign_ups: oldSignUps,
            path_elements: userStateTreePathElements,
            attester_ids: attesterIds,
            pos_reps: posReps,
            neg_reps: negReps,
            graffities: graffities,
            overwrite_graffities: overwriteGraffitis,
            sign_ups: signUps,
            selectors: selectors,
            hash_chain_starter: hashChainStarter,
            input_blinded_user_state: inputBlindedUserState,
        }
        
        let error
        try {
            await executeCircuit(circuit, circuitInputs)
        } catch (e) {
            error = e
            expect(true).to.be.true
        } finally {
            if (!error) throw Error("Root mismatch results from wrong path elements should throw error")
        }

        userStateTreePathElements[indexWrongPathElements].reverse()
    })

    it('process attestations with incorrect number of elements should fail', async () => {
        const wrongAttesterIds = attesterIds.concat([BigInt(4)])
        const circuitInputs = {
            epoch: epoch,
            from_nonce: toNonce,
            to_nonce: toNonce,
            identity_nullifier: user['identityNullifier'],
            intermediate_user_state_tree_roots: intermediateUserStateTreeRoots,
            old_pos_reps: oldPosReps,
            old_neg_reps: oldNegReps,
            old_graffities: oldGraffities,
            old_sign_ups: oldSignUps,
            path_elements: userStateTreePathElements,
            attester_ids: wrongAttesterIds,
            pos_reps: posReps,
            neg_reps: negReps,
            graffities: graffities,
            overwrite_graffities: overwriteGraffitis,
            sign_ups: signUps,
            selectors: selectors,
            hash_chain_starter: hashChainStarter,
            input_blinded_user_state: inputBlindedUserState,
        }

        let error
        try {
            await executeCircuit(circuit, circuitInputs)
        } catch (e) {
            error = e
            expect(true).to.be.true
        } finally {
            if (!error) throw Error("Incorrect number of elements should throw error")
        }
    })
})