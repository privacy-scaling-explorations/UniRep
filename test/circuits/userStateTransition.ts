import * as path from 'path'
import { expect } from "chai"
import { genRandomSalt, hash5, hashLeftRight, stringifyBigInts, genIdentity, genIdentityCommitment, SparseMerkleTreeImpl, IncrementalQuinTree, SnarkBigInt } from "../../crypto"
import { compileAndLoadCircuit, executeCircuit, getSignalByName, genProofAndPublicSignals, verifyProof } from "../../circuits/utils"
import { Reputation, genEpochKey } from '../../core'
import { genNewUserStateTree, genNewEpochTree } from '../utils'
import { circuitEpochTreeDepth, circuitGlobalStateTreeDepth, numEpochKeyNoncePerEpoch } from "../../config/testLocal"

describe('User State Transition circuits', function () {
    this.timeout(600000)

    const epoch = 1
    const user = genIdentity()

    describe('Epoch key exists', () => {

        let circuit

        const nonce = numEpochKeyNoncePerEpoch - 1
        const testEpochTreeDepth = 32
        const epochKey: SnarkBigInt = genEpochKey(user['identityNullifier'], epoch, nonce, testEpochTreeDepth)

        let epochTree: SparseMerkleTreeImpl, epochTreeRoot, epochTreePathElements

        let hashChainResult: SnarkBigInt

        before(async () => {
            const startCompileTime = Math.floor(new Date().getTime() / 1000)
            const circuitPath = path.join(__dirname, '../../circuits/test/epochKeyExists_test.circom')
            circuit = await compileAndLoadCircuit(circuitPath)
            const endCompileTime = Math.floor(new Date().getTime() / 1000)
            console.log(`Compile time: ${endCompileTime - startCompileTime} seconds`)

            // Epoch tree
            epochTree = await genNewEpochTree("circuit")

            hashChainResult = genRandomSalt()

            await epochTree.update(epochKey, hashChainResult)
            
            epochTreePathElements = await epochTree.getMerkleProof(epochKey)
            epochTreeRoot = epochTree.getRootHash()
        })

        it('Existed epoch key should pass check', async () => {
            const circuitInputs = {
                identity_nullifier: user['identityNullifier'],
                epoch: epoch,
                nonce: nonce,
                hash_chain_result: hashChainResult,
                epoch_tree_root: epochTreeRoot,
                path_elements: epochTreePathElements
            }


            const witness = await executeCircuit(circuit, circuitInputs)
        })
    })

    describe('User State Transition', () => {

        let circuit

        const EPK_NONCE_PER_EPOCH = numEpochKeyNoncePerEpoch
        const expectedNumAttestationsMade = 5

        let GSTZERO_VALUE = 0, GSTree: IncrementalQuinTree, GSTreeRoot, GSTreeProof, newGSTLeaf
        let epochTree: SparseMerkleTreeImpl, epochTreeRoot, epochTreePathElements: any[]
        let userStateTree: SparseMerkleTreeImpl
        let intermediateUserStateTreeRoots
        let blindedUserState: BigInt[]
        let blindedHashChain: BigInt[]
        const signUp = 1
        const startEpochKeyNonce = 0
        const endEpochKeyNonce = EPK_NONCE_PER_EPOCH - 1

        let reputationRecords = {}
        let hashChainResults: BigInt[] = []
        let hashedLeaf

        before(async () => {
            const startCompileTime = Math.floor(new Date().getTime() / 1000)
            const circuitPath = path.join(__dirname, '../../circuits/test/userStateTransition_test.circom')
            circuit = await compileAndLoadCircuit(circuitPath)
            const endCompileTime = Math.floor(new Date().getTime() / 1000)
            console.log(`Compile time: ${endCompileTime - startCompileTime} seconds`)

            // Epoch tree
            epochTree = await genNewEpochTree("circuit")

            // User state tree
            userStateTree = await genNewUserStateTree()
            intermediateUserStateTreeRoots = []
            blindedUserState = []
            blindedHashChain = []
            epochTreePathElements = []

            // Bootstrap user state for the first `expectedNumAttestationsMade` attesters
            for (let i = 1; i < expectedNumAttestationsMade; i++) {
                const  attesterId = BigInt(i)
                if (reputationRecords[attesterId.toString()] === undefined) {
                    reputationRecords[attesterId.toString()] = new Reputation(
                        BigInt(Math.floor(Math.random() * 100)),
                        BigInt(Math.floor(Math.random() * 100)),
                        genRandomSalt(),
                        BigInt(signUp)
                    )
                }
                await userStateTree.update(BigInt(attesterId), reputationRecords[attesterId.toString()].hash())
            }
            intermediateUserStateTreeRoots.push(userStateTree.getRootHash())
            blindedUserState.push(hash5([user['identityNullifier'], userStateTree.getRootHash(), BigInt(epoch), BigInt(startEpochKeyNonce)]))

            // Global state tree
            GSTree = new IncrementalQuinTree(circuitGlobalStateTreeDepth, GSTZERO_VALUE, 2)
            const commitment = genIdentityCommitment(user)
            hashedLeaf = hashLeftRight(commitment, userStateTree.getRootHash())
            GSTree.insert(hashedLeaf)
            GSTreeProof = GSTree.genMerklePath(0)
            GSTreeRoot = GSTree.root

            // Begin generating and processing attestations
            for (let nonce = 0; nonce < EPK_NONCE_PER_EPOCH; nonce++) {
                // Each epoch key has `ATTESTATIONS_PER_EPOCH_KEY` of attestations so
                // interval between starting index of each epoch key is `ATTESTATIONS_PER_EPOCH_KEY`.
                const epochKey = genEpochKey(user['identityNullifier'], epoch, nonce, circuitEpochTreeDepth)
                const hashChainResult = genRandomSalt()

                // Blinded hash chain result
                hashChainResults.push(hashChainResult)
                blindedHashChain.push(hash5([user['identityNullifier'], hashChainResult, BigInt(epoch), BigInt(nonce)]))

                // Seal hash chain of this epoch key
                const sealedHashChainResult = hashLeftRight(BigInt(1), hashChainResult)

                // Update epoch tree
                await epochTree.update(epochKey, sealedHashChainResult)
            }

            const intermediateUserStateTreeRoot = genRandomSalt()
            intermediateUserStateTreeRoots.push(intermediateUserStateTreeRoot)
            blindedUserState.push(hash5([user['identityNullifier'], intermediateUserStateTreeRoot, BigInt(epoch), BigInt(endEpochKeyNonce)]))

            // Compute new GST Leaf
            const latestUSTRoot = intermediateUserStateTreeRoots[1]
            newGSTLeaf = hashLeftRight(commitment, latestUSTRoot)

            for (let nonce = 0; nonce < EPK_NONCE_PER_EPOCH; nonce++) {
                const epochKey = genEpochKey(user['identityNullifier'], epoch, nonce, circuitEpochTreeDepth)
                // Get epoch tree root and merkle proof for this epoch key
                epochTreePathElements.push(await epochTree.getMerkleProof(epochKey))
            }
            epochTreeRoot = epochTree.getRootHash()
        })

        describe('Process user state transition proof', () => {
            it('Valid user state update inputs should work', async () => {
                const circuitInputs = {
                    epoch: epoch,
                    blinded_user_state: blindedUserState,
                    intermediate_user_state_tree_roots: intermediateUserStateTreeRoots,
                    start_epoch_key_nonce: startEpochKeyNonce,
                    end_epoch_key_nonce: endEpochKeyNonce,
                    identity_pk: user['keypair']['pubKey'],
                    identity_nullifier: user['identityNullifier'],
                    identity_trapdoor: user['identityTrapdoor'],
                    GST_path_elements: GSTreeProof.pathElements,
                    GST_path_index: GSTreeProof.indices,
                    GST_root: GSTreeRoot,
                    epk_path_elements: epochTreePathElements,
                    hash_chain_results: hashChainResults,
                    blinded_hash_chain_results: blindedHashChain,
                    epoch_tree_root: epochTreeRoot
                }
                const witness = await executeCircuit(circuit, circuitInputs)
                const _newGSTLeaf = getSignalByName(circuit, witness, 'main.new_GST_leaf')
                expect(_newGSTLeaf, 'new GST leaf mismatch').to.equal(newGSTLeaf)

                const startTime = new Date().getTime()
                const results = await genProofAndPublicSignals('userStateTransition', stringifyBigInts(circuitInputs))
                const endTime = new Date().getTime()
                console.log(`Gen Proof time: ${endTime - startTime} ms (${Math.floor((endTime - startTime) / 1000)} s)`)
                const isValid = await verifyProof('userStateTransition', results['proof'], results['publicSignals'])
                expect(isValid).to.be.true
            })
        })
    })
})