import * as argparse from 'argparse' 
import * as fs from 'fs'
import * as path from 'path'
import * as shell from 'shelljs'
import { genIdentity, genIdentityCommitment } from 'libsemaphore'

import { genSnarkVerifierSol } from './genVerifier'
import {
    buildProveReputationTestCircuit,
    compileAndLoadCircuit,
    executeCircuit,
    genTestProofAndPublicSignals,
    genVerifyReputationProofAndPublicSignals,
    verifyProveReputationProof,
    verifyTestProof,
} from '../test/circuits/utils'

import { genAttestationNullifier, genEpochKey, genEpochKeyNullifier, genNewEpochTreeForBenchmark, genNewNullifierTree, genNewNullifierTreeForBenchmark, genNewUserStateTree, genNewUserStateTreeForBenchmark, SMT_ONE_LEAF } from '../test/utils'
import { genRandomSalt, hash5, hashLeftRight, hashOne, IncrementalQuinTree, SnarkBigInt, stringifyBigInts, unstringifyBigInts } from 'maci-crypto'

import { Attestation, Reputation } from "../core"
import { DEFAULT_AIRDROPPED_KARMA } from '../config/socialMedia'


(async function() {
    const zkutilPath = "~/.cargo/bin/zkutil"
    const parser = new argparse.ArgumentParser({ 
        description: 'Compile a circom circuit and generate its proving key, verification key, and Solidity verifier'
    })

    parser.addArgument(
        ['-gst', '--global-state-tree'],
        {
            help: 'The depth of global state tree',
            required: true
        }
    )

    parser.addArgument(
        ['-ust', '--user-state-tree'],
        {
            help: 'The depth of user state tree',
            required: true
        }
    )

    parser.addArgument(
        ['-ept', '--epoch-tree'],
        {
            help: 'The depth of epoch tree',
            required: true
        }
    )

    parser.addArgument(
        ['-nt', '--nullifier-tree'],
        {
            help: 'The depth of nullifier tree',
            required: true
        }
    )

    parser.addArgument(
        ['-epk', '--epoch-key-per-epoch'],
        {
            help: 'The number of epoch keys the user can have per epoch',
            required: true
        }
    )

    parser.addArgument(
        ['-a', '--attestation'],
        {
            help: 'The number of attestations a user can have per epoch key',
            required: true
        }
    )

    const date = Date.now()
    const args = parser.parseArgs()
    const GSTDepth = args.global_state_tree
    const USTDepth = args.user_state_tree
    const epochTreeDepth = args.epoch_tree
    const nullifierTreeDepth = args.nullifier_tree
    const epochKeyNoncePerEpoch = args.epoch_key_per_epoch
    const attestationNum = args.attestation
    const circuitName = "userStateTransition"
    let testCircuitContent
    
    const dirPath = path.join(__dirname, '../circuits/benchmark/')
    const circomPath = path.join(__dirname, `../circuits/benchmark/${circuitName}_${date}.circom`)
    const circuitOut = path.join(__dirname, `../circuits/benchmark/${circuitName}_${date}.r1cs`)
    const wasmOut = path.join(__dirname, `../circuits/benchmark/${circuitName}_${date}.wasm`)
    const symOut = path.join(__dirname, `../circuits/benchmark/${circuitName}_${date}.sym`)
    const paramsOut = path.join(__dirname, `../circuits/benchmark/${circuitName}_${date}.params`)

    // create .circom file
    testCircuitContent = `include "../userStateTransition.circom" \n\ncomponent main = UserStateTransition(${GSTDepth}, ${epochTreeDepth}, ${nullifierTreeDepth}, ${USTDepth}, ${attestationNum}, ${epochKeyNoncePerEpoch}, ${attestationNum*epochKeyNoncePerEpoch})`

    try{
        fs.mkdirSync(dirPath, { recursive: true })
    } catch(e){
        console.log('Cannot create folder ', e);
    }
    fs.writeFileSync(circomPath, testCircuitContent)

    // // Check if the input circom file exists
    // const inputFileExists = fileExists(circomPath)

    // // Exit if it does not
    // if (!inputFileExists) {
    //     console.error('File does not exist:', circomPath)
    //     return 1
    // }

    // Set memory options for node
    shell.env['NODE_OPTIONS'] = '--max-old-space-size=4096'

    // Compile the .circom file
    const startCompileTime = Math.floor(new Date().getTime())
    console.log(`Compiling ${circomPath}...`)
    shell.exec(`node ./node_modules/circom/cli.js ${circomPath} -r ${circuitOut} -w ${wasmOut} -s ${symOut}`)
    console.log('Generated', circuitOut, 'and', wasmOut)
    const endCompileTime = Math.floor(new Date().getTime())
    console.log(`Compile time: ${endCompileTime - startCompileTime} ms`)
    
    // Generate params file
    console.log('Generating params file...')
    shell.exec(`${zkutilPath} setup -c ${circuitOut} -p ${paramsOut}`)

    // Generate inputs for test circuit
    // User state
    const epoch = 1
    const nonce = epochKeyNoncePerEpoch - 1
    const user = genIdentity()
    const proveKarmaAmount = 3
    const nonceStarter = 0
    const epochKeyNonce = 0
    const epochKey = genEpochKey(user['identityNullifier'], epoch, epochKeyNonce, epochTreeDepth)
    let minRep = null
    let reputationRecords = {}
    const userStateTree = await genNewUserStateTreeForBenchmark(USTDepth)
    let intermediateUserStateTreeRoots, userStateLeafPathElements
    let oldPosReps, oldNegReps, oldGraffities
    let attesterIds: BigInt[], posReps: BigInt[], negReps: BigInt[], graffities: SnarkBigInt[], overwriteGraffitis: boolean[]
    let selectors: number[] = []
    let nullifiers: BigInt[]
    let hashChainResults: BigInt[] = []
    let currentEpochPosRep = 0
    let currentEpochNegRep = 0
    const maxNumAttesters = 2 ** USTDepth
    const expectedNumAttestationsMade = Math.floor(maxNumAttesters / 2)

    intermediateUserStateTreeRoots = []
    userStateLeafPathElements = []
    oldPosReps = []
    oldNegReps = []
    oldGraffities = []
    // Bootstrap user state
    for (let i = 1; i < maxNumAttesters; i++) {
        const  attesterId = BigInt(i)
        if (reputationRecords[attesterId.toString()] === undefined) {
            reputationRecords[attesterId.toString()] = new Reputation(
                BigInt(Math.floor(Math.random() * 100)),
                BigInt(Math.floor(Math.random() * 100)),
                genRandomSalt(),
            )
        }
        await userStateTree.update(BigInt(attesterId), reputationRecords[attesterId.toString()].hash())
    }
    intermediateUserStateTreeRoots.push(userStateTree.getRootHash())

    const userStateRoot = userStateTree.getRootHash()
    
    // Global state tree
    let GSTZERO_VALUE = 0
    const transitionedPosRep = 5
    const transitionedNegRep = 0
    const GSTree = new IncrementalQuinTree(GSTDepth, GSTZERO_VALUE, 2)
    const commitment = genIdentityCommitment(user)
    const hashedLeaf = hash5([
        commitment, 
        userStateRoot,
        BigInt(transitionedPosRep),
        BigInt(transitionedNegRep),
        BigInt(0)
    ])
    
    GSTree.insert(hashedLeaf)
    const GSTreeProof = GSTree.genMerklePath(0)
    const GSTreeRoot = GSTree.root

    attesterIds = []
    posReps = []
    negReps = []
    graffities = []
    overwriteGraffitis = []
    const TOTAL_NUM_ATTESTATIONS = epochKeyNoncePerEpoch * attestationNum

    let numAttestationsMade = 0
    for (let i = 0; i < TOTAL_NUM_ATTESTATIONS; i++) {
        if (numAttestationsMade < expectedNumAttestationsMade) {
            const s = Math.floor(Math.random() * 2)
            selectors.push(s)
            if (s == 1) numAttestationsMade++
        } else {
            selectors.push(0)
        }
    }

    // Epoch tree
    const epochTree = await genNewEpochTreeForBenchmark(epochTreeDepth)
    
    // Begin generating and processing attestations
    nullifiers = []
    let epochTreePathElements: any[] = []
    let hashChainResult: BigInt
    const attesterToNonceMap = {}
    let startIndex
    for (let nonce = 0; nonce < epochKeyNoncePerEpoch; nonce++) {
        startIndex = nonce * attestationNum
        attesterToNonceMap[nonce] = []
        hashChainResult = BigInt(0)
        // Each epoch key has `ATTESTATIONS_PER_EPOCH_KEY` of attestations so
        // interval between starting index of each epoch key is `ATTESTATIONS_PER_EPOCH_KEY`.
        const epochKey = genEpochKey(user['identityNullifier'], epoch, nonce, epochTreeDepth)
        for (let i = 0; i < attestationNum; i++) {
            // attesterId ranges from 1 to (maxNumAttesters - 1)
            let attesterId = BigInt(1 + Math.floor(Math.random() * (maxNumAttesters - 1)))
            // re-sample attesterId if it is already in the list
            while (attesterToNonceMap[nonce].indexOf(attesterId) >= 0) {
                attesterId = BigInt(1 + Math.floor(Math.random() * (maxNumAttesters - 1)))
            }
            const attestation: Attestation = new Attestation(
                attesterId,
                BigInt(Math.floor(Math.random() * 100)),
                BigInt(Math.floor(Math.random() * 100)),
                genRandomSalt(),
                true,
            )
            // If nullifier tree is too small, it's likely that nullifier would be zero and
            // this conflicts with the reserved zero leaf of nullifier tree.
            // In this case, force selector to be zero.
            const nullifier = genAttestationNullifier(user['identityNullifier'], attesterId, epoch, epochKey, nullifierTreeDepth)
            if ( nullifier == BigInt(0) ) {
                if (selectors[startIndex + i] == 1) numAttestationsMade--
                selectors[startIndex + i] = 0
            }

            if ( selectors[startIndex + i] == 1) {
                attesterToNonceMap[nonce].push(attesterId)

                attesterIds.push(attesterId)
                posReps.push(attestation['posRep'])
                negReps.push(attestation['negRep'])
                graffities.push(attestation['graffiti'])
                overwriteGraffitis.push(attestation['overwriteGraffiti'])

                oldPosReps.push(reputationRecords[attesterId.toString()]['posRep'])
                oldNegReps.push(reputationRecords[attesterId.toString()]['negRep'])
                oldGraffities.push(reputationRecords[attesterId.toString()]['graffiti'])

                // Get old attestation record proof
                const oldReputationRecordProof = await userStateTree.getMerkleProof(BigInt(attesterId))
                userStateLeafPathElements.push(oldReputationRecordProof)

                // Update attestation record
                reputationRecords[attesterId.toString()]['posRep'] = attestation['posRep']
                reputationRecords[attesterId.toString()]['negRep'] = attestation['negRep']
                currentEpochPosRep += Number(attestation['posRep'])
                currentEpochNegRep += Number(attestation['negRep'])
                if (attestation['overwriteGraffiti']) reputationRecords[attesterId.toString()]['graffiti'] = attestation['graffiti']
                await userStateTree.update(BigInt(attesterId), reputationRecords[attesterId.toString()].hash())

                const attestation_hash = attestation.hash()
                hashChainResult = hashLeftRight(attestation_hash, hashChainResult)

                nullifiers.push(nullifier)
            } else {
                attesterIds.push(BigInt(0))
                posReps.push(BigInt(0))
                negReps.push(BigInt(0))
                graffities.push(BigInt(0))
                overwriteGraffitis.push(false)

                oldPosReps.push(BigInt(0))
                oldNegReps.push(BigInt(0))
                oldGraffities.push(BigInt(0))

                const USTLeafZeroPathElements = await userStateTree.getMerkleProof(BigInt(0))
                userStateLeafPathElements.push(USTLeafZeroPathElements)

                nullifiers.push(BigInt(0))
            }
            intermediateUserStateTreeRoots.push(userStateTree.getRootHash())
        }
        // Seal hash chain of this epoch key
        hashChainResult = hashLeftRight(BigInt(1), hashChainResult)
        hashChainResults.push(hashChainResult)
        // Update epoch tree
        await epochTree.update(epochKey, hashChainResult)
    }

    // Compute new GST Leaf
    const latestUSTRoot = intermediateUserStateTreeRoots[TOTAL_NUM_ATTESTATIONS]
    const newGSTLeaf = hash5([
        commitment,
        latestUSTRoot,
        BigInt(transitionedPosRep + currentEpochPosRep + DEFAULT_AIRDROPPED_KARMA),
        BigInt(transitionedNegRep + currentEpochNegRep),
        BigInt(0)
    ])

    for (let nonce = 0; nonce < epochKeyNoncePerEpoch; nonce++) {
        const epochKey = genEpochKey(user['identityNullifier'], epoch, nonce, epochTreeDepth)
        // Get epoch tree root and merkle proof for this epoch key
        epochTreePathElements.push(await epochTree.getMerkleProof(epochKey))
    }
    const epochTreeRoot = epochTree.getRootHash()

    const circuitInputs = {
        epoch: epoch,
        intermediate_user_state_tree_roots: intermediateUserStateTreeRoots,
        old_pos_reps: oldPosReps,
        old_neg_reps: oldNegReps,
        old_graffities: oldGraffities,
        UST_path_elements: userStateLeafPathElements,
        identity_pk: user['keypair']['pubKey'],
        identity_nullifier: user['identityNullifier'],
        identity_trapdoor: user['identityTrapdoor'],
        user_state_hash: hashedLeaf,
        old_positive_karma: BigInt(transitionedPosRep),
        old_negative_karma: BigInt(transitionedNegRep),
        GST_path_elements: GSTreeProof.pathElements,
        GST_path_index: GSTreeProof.indices,
        GST_root: GSTreeRoot,
        selectors: selectors,
        attester_ids: attesterIds,
        pos_reps: posReps,
        neg_reps: negReps,
        graffities: graffities,
        overwrite_graffitis: overwriteGraffitis,
        positive_karma: BigInt(transitionedPosRep + currentEpochPosRep + DEFAULT_AIRDROPPED_KARMA),
        negative_karma: BigInt(transitionedNegRep + currentEpochNegRep),
        airdropped_karma: DEFAULT_AIRDROPPED_KARMA,
        epk_path_elements: epochTreePathElements,
        hash_chain_results: hashChainResults,
        epoch_tree_root: epochTreeRoot
    }

    // generate circuit proof

    const inputJsonPath = path.join(__dirname, `../circuits/benchmark/${circuitName}_${date}.input.json`)
    const witnessPath = path.join(__dirname, `../circuits/benchmark/${circuitName}_${date}.witness.wtns`)
    const witnessJsonPath = path.join(__dirname, `../circuits/benchmark/${circuitName}_${date}.witness.json`)
    const proofPath = path.join(__dirname, `../circuits/benchmark/${circuitName}_${date}.proof.json`)
    const publicJsonPath = path.join(__dirname, `../circuits/benchmark/${circuitName}_${date}.publicSignals.json`)

    fs.writeFileSync(inputJsonPath, JSON.stringify(stringifyBigInts(circuitInputs)))

    const startGenProofTime = Math.floor(new Date().getTime())
    const snarkjsCmd = 'node ' + path.join(__dirname, '../node_modules/snarkjs/build/cli.cjs')
    const witnessCmd = `${snarkjsCmd} wc ${wasmOut} ${inputJsonPath} ${witnessPath}`

    shell.exec(witnessCmd)

    const witnessJsonCmd = `${snarkjsCmd} wej ${witnessPath} ${witnessJsonPath}`
    shell.exec(witnessJsonCmd)

    const proveCmd = `${zkutilPath} prove -c ${circuitOut} -p ${paramsOut} -w ${witnessJsonPath} -r ${proofPath} -o ${publicJsonPath}`

    shell.exec(proveCmd)
    const endGenProofTime = Math.floor(new Date().getTime())
    console.log(`Generate proof time: ${endGenProofTime - startGenProofTime} ms`)

    shell.rm('-f', witnessPath)
    shell.rm('-f', witnessJsonPath)
    shell.rm('-f', inputJsonPath)

    // verify proof
    const startVerifyTime = Math.floor(new Date().getTime())
    const verifyCmd = `${zkutilPath} verify -p ${paramsOut} -r ${proofPath} -i ${publicJsonPath}`
    const output = shell.exec(verifyCmd).stdout.trim()
    const endVerifyTime = Math.floor(new Date().getTime())
    console.log(`Verify proof time: ${endVerifyTime - startVerifyTime} ms`)

    shell.rm('-f', circuitOut)
    shell.rm('-f', wasmOut)
    shell.rm('-f', symOut)
    shell.rm('-f', paramsOut)
    shell.rm('-f', proofPath)
    shell.rm('-f', publicJsonPath)

    if(output != "Proof is correct"){
        console.log('ERROR')
        console.log(circuitInputs)
    }

    return 0
})();
