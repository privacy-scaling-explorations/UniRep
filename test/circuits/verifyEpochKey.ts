import * as path from 'path'
import { expect } from "chai"
import { genRandomSalt, hashLeftRight, genIdentity, genIdentityCommitment, IncrementalQuinTree,  stringifyBigInts, } from "../../crypto"
import { compileAndLoadCircuit, executeCircuit, genProofAndPublicSignals, verifyProof } from "../../circuits/utils"
import { numEpochKeyNoncePerEpoch, circuitEpochTreeDepth, circuitGlobalStateTreeDepth } from "../../config/testLocal"
import { genEpochKey } from '../../core'


describe('Verify Epoch Key circuits', function () {
    this.timeout(300000)

    let circuit
    let ZERO_VALUE = 0

    const maxEPK = BigInt(2 ** circuitEpochTreeDepth)

    let id, commitment, stateRoot
    let tree, proof, root
    let nonce, currentEpoch, epochKey

    before(async () => {
        const circuitPath = path.join(__dirname, '../../circuits/test/verifyEpochKey_test.circom')
        const startCompileTime = Math.floor(new Date().getTime() / 1000)
        circuit = await compileAndLoadCircuit(circuitPath)
        const endCompileTime = Math.floor(new Date().getTime() / 1000)
        console.log(`Compile time: ${endCompileTime - startCompileTime} seconds`)

        tree = new IncrementalQuinTree(circuitGlobalStateTreeDepth, ZERO_VALUE, 2)
        id = genIdentity()
        commitment = genIdentityCommitment(id)
        stateRoot = genRandomSalt()

        const hashedStateLeaf = hashLeftRight(commitment.toString(), stateRoot.toString())
        tree.insert(BigInt(hashedStateLeaf.toString()))
        proof = tree.genMerklePath(0)
        root = tree.root

        nonce = 0
        currentEpoch = 1
        epochKey = genEpochKey(id['identityNullifier'], currentEpoch, nonce, circuitEpochTreeDepth)
    })

    it('Valid epoch key should pass check', async () => {
        // Check if every valid nonce works
        for (let i = 0; i < numEpochKeyNoncePerEpoch; i++) {
            const n = i
            const epk = genEpochKey(id['identityNullifier'], currentEpoch, n, circuitEpochTreeDepth)
            
            const circuitInputs = {
                GST_path_elements: proof.pathElements,
                GST_path_index: proof.indices,
                GST_root: root,
                identity_pk: id['keypair']['pubKey'],
                identity_nullifier: id['identityNullifier'], 
                identity_trapdoor: id['identityTrapdoor'],
                user_tree_root: stateRoot,
                nonce: n,
                epoch: currentEpoch,
                epoch_key: epk,
            }
            const witness = await executeCircuit(circuit, circuitInputs)
            const startTime = new Date().getTime()
            const results = await genProofAndPublicSignals('verifyEpochKey', stringifyBigInts(circuitInputs))
            const endTime = new Date().getTime()
            console.log(`Gen Proof time: ${endTime - startTime} ms (${Math.floor((endTime - startTime) / 1000)} s)`)
            const isValid = await verifyProof('verifyEpochKey', results['proof'], results['publicSignals'])
            expect(isValid).to.be.true
        }
    })

    it('Invalid epoch key should not pass check', async () => {
        // Validate against invalid epoch key
        const invalidEpochKey1 = maxEPK
        let circuitInputs = {
            GST_path_elements: proof.pathElements,
            GST_path_index: proof.indices,
            GST_root: root,
            identity_pk: id['keypair']['pubKey'],
            identity_nullifier: id['identityNullifier'], 
            identity_trapdoor: id['identityTrapdoor'],
            user_tree_root: stateRoot,
            nonce: nonce,
            epoch: currentEpoch,
            epoch_key: invalidEpochKey1,
        }
        let error
        try {
            await executeCircuit(circuit, circuitInputs)
        } catch (e) {
            error = e
            expect(true).to.be.true
        } finally {
            if (!error) throw Error("Epoch key too large should throw error")
        }
    })

    it('Wrong Id should not pass check', async () => {
        const fakeId = genIdentity()
        const circuitInputs = {
            GST_path_elements: proof.pathElements,
            GST_path_index: proof.indices,
            GST_root: root,
            identity_pk: fakeId['keypair']['pubKey'],
            identity_nullifier: fakeId['identityNullifier'], 
            identity_trapdoor: fakeId['identityTrapdoor'],
            user_tree_root: stateRoot,
            nonce: nonce,
            epoch: currentEpoch,
            epoch_key: epochKey,
        }
        let error
        try {
            await executeCircuit(circuit, circuitInputs)
        } catch (e) {
            error = e
            expect(true).to.be.true
        } finally {
            if (!error) throw Error("Wrong Id should throw error")
        }
    })

    it('Mismatched GST tree root should not pass check', async () => {
        const otherTreeRoot = genRandomSalt()
        const circuitInputs = {
            GST_path_elements: proof.pathElements,
            GST_path_index: proof.indices,
            GST_root: root,
            identity_pk: id['keypair']['pubKey'],
            identity_nullifier: id['identityNullifier'], 
            identity_trapdoor: id['identityTrapdoor'],
            user_tree_root: otherTreeRoot,
            nonce: nonce,
            epoch: currentEpoch,
            epoch_key: epochKey,
        }
        let error
        try {
            await executeCircuit(circuit, circuitInputs)
        } catch (e) {
            error = e
            expect(true).to.be.true
        } finally {
            if (!error) throw Error("Wrong GST Root should throw error")
        }
    })

    it('Invalid nonce should not pass check', async () => {
        const invalidNonce = numEpochKeyNoncePerEpoch
        const circuitInputs = {
            GST_path_elements: proof.pathElements,
            GST_path_index: proof.indices,
            GST_root: root,
            identity_pk: id['keypair']['pubKey'],
            identity_nullifier: id['identityNullifier'], 
            identity_trapdoor: id['identityTrapdoor'],
            user_tree_root: stateRoot,
            nonce: invalidNonce,
            epoch: currentEpoch,
            epoch_key: epochKey,
        }
        let error
        try {
            await executeCircuit(circuit, circuitInputs)
        } catch (e) {
            error = e
            expect(true).to.be.true
        } finally {
            if (!error) throw Error("Invalid nonce should throw error")
        }
    })

    it('Invalid epoch should not pass check', async () => {
        let invalidEpoch, invalidEpochKey
        invalidEpoch = currentEpoch + 1
        invalidEpochKey = genEpochKey(id['identityNullifier'], invalidEpoch, nonce, circuitEpochTreeDepth)
        while (invalidEpochKey == epochKey) {
            invalidEpoch += 1
            invalidEpochKey = genEpochKey(id['identityNullifier'], invalidEpoch, nonce, circuitEpochTreeDepth)
        }
        const circuitInputs = {
            GST_path_elements: proof.pathElements,
            GST_path_index: proof.indices,
            GST_root: root,
            identity_pk: id['keypair']['pubKey'],
            identity_nullifier: id['identityNullifier'], 
            identity_trapdoor: id['identityTrapdoor'],
            user_tree_root: stateRoot,
            nonce: nonce,
            epoch: invalidEpoch,
            epoch_key: epochKey,
        }
        let error
        try {
            await executeCircuit(circuit, circuitInputs)
        } catch (e) {
            error = e
            expect(true).to.be.true
        } finally {
            if (!error) throw Error("Wrong epoch should throw error")
        }
    })
})