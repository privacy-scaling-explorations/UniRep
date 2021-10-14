import * as path from 'path'
import { expect } from "chai"
import { genRandomSalt, hash5, hashLeftRight, stringifyBigInts, genIdentity, genIdentityCommitment, SparseMerkleTreeImpl, IncrementalQuinTree } from "../../crypto"
import { compileAndLoadCircuit, executeCircuit, getSignalByName, genProofAndPublicSignals, verifyProof } from "../../circuits/utils"
import { Reputation } from '../../core'
import { genNewUserStateTree } from '../utils'
import { circuitGlobalStateTreeDepth } from "../../config/testLocal"

describe('User State Transition circuits', function () {
    this.timeout(60000)

    const user = genIdentity()

    describe('Start User State Transition', () => {

        let circuit
        const epoch = BigInt(1)
        const expectedNumAttestationsMade = 5

        let GSTZERO_VALUE = 0, GSTree: IncrementalQuinTree, GSTreeRoot, GSTreeProof
        let userStateTree: SparseMerkleTreeImpl

        let reputationRecords = {}
        let hashedLeaf
        const zeroHashChain = BigInt(0)
        const nonce = BigInt(0)
        const signUp = 1

        before(async () => {
            const startCompileTime = Math.floor(new Date().getTime() / 1000)
            const circuitPath = path.join(__dirname, '../../circuits/test/startTransition_test.circom')
            circuit = await compileAndLoadCircuit(circuitPath)
            const endCompileTime = Math.floor(new Date().getTime() / 1000)
            console.log(`Compile time: ${endCompileTime - startCompileTime} seconds`)

            // User state tree
            userStateTree = await genNewUserStateTree()

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

            // Global state tree
            GSTree = new IncrementalQuinTree(circuitGlobalStateTreeDepth, GSTZERO_VALUE, 2)
            const commitment = genIdentityCommitment(user)
            hashedLeaf = hashLeftRight(commitment, userStateTree.getRootHash())
            GSTree.insert(hashedLeaf)
            GSTreeProof = GSTree.genMerklePath(0)
            GSTreeRoot = GSTree.root
        })

        describe('Start process user state tree', () => {
            it('Valid user state update inputs should work', async () => {
                const circuitInputs = {
                    epoch: epoch,
                    nonce: nonce,
                    user_tree_root: userStateTree.getRootHash(),
                    identity_pk: user['keypair']['pubKey'],
                    identity_nullifier: user['identityNullifier'],
                    identity_trapdoor: user['identityTrapdoor'],
                    GST_path_elements: GSTreeProof.pathElements,
                    GST_path_index: GSTreeProof.indices,
                    GST_root: GSTreeRoot
                }
                const witness = await executeCircuit(circuit, circuitInputs)
                const outputUserState = getSignalByName(circuit, witness, 'main.blinded_user_state')
                const expectedUserState = hash5([user['identityNullifier'], userStateTree.getRootHash(), epoch, nonce])
                expect(outputUserState).to.equal(expectedUserState)

                const outputHashChainResult = getSignalByName(circuit, witness, 'main.blinded_hash_chain_result')
                const expectedHashChainResult = hash5([user['identityNullifier'], zeroHashChain, epoch, nonce])
                expect(outputHashChainResult).to.equal(expectedHashChainResult)

                const startTime = new Date().getTime()
                const results = await genProofAndPublicSignals('startTransition', stringifyBigInts(circuitInputs))
                const endTime = new Date().getTime()
                console.log(`Gen Proof time: ${endTime - startTime} ms (${Math.floor((endTime - startTime) / 1000)} s)`)
                const isValid = await verifyProof('startTransition', results['proof'], results['publicSignals'])
                expect(isValid).to.be.true
            })

            it('User can start with different epoch key nonce', async () => {
                const newNonce = BigInt(1)
                const circuitInputs = {
                    epoch: epoch,
                    nonce: newNonce,
                    user_tree_root: userStateTree.getRootHash(),
                    identity_pk: user['keypair']['pubKey'],
                    identity_nullifier: user['identityNullifier'],
                    identity_trapdoor: user['identityTrapdoor'],
                    GST_path_elements: GSTreeProof.pathElements,
                    GST_path_index: GSTreeProof.indices,
                    GST_root: GSTreeRoot
                }
                const witness = await executeCircuit(circuit, circuitInputs)
                const outputUserState = getSignalByName(circuit, witness, 'main.blinded_user_state')
                const expectedUserState = hash5([user['identityNullifier'], userStateTree.getRootHash(), epoch, newNonce])
                expect(outputUserState).to.equal(expectedUserState)

                const outputHashChainResult = getSignalByName(circuit, witness, 'main.blinded_hash_chain_result')
                const expectedHashChainResult = hash5([user['identityNullifier'], zeroHashChain, epoch, newNonce])
                expect(outputHashChainResult).to.equal(expectedHashChainResult)
            })
        })
    })
})