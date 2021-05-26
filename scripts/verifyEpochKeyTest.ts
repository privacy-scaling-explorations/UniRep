import * as argparse from 'argparse' 
import * as fs from 'fs'
import * as path from 'path'
import * as shell from 'shelljs'
import { genIdentity, genIdentityCommitment } from 'libsemaphore'

import { genEpochKey} from '../test/utils'
import { genRandomSalt, hash5, IncrementalQuinTree, stringifyBigInts } from 'maci-crypto'


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
        ['-ept', '--epoch-tree'],
        {
            help: 'The depth of epoch tree',
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

    const date = Date.now()
    const args = parser.parseArgs()
    const GSTDepth = args.global_state_tree
    const epochTreeDepth = args.epoch_tree
    const epochKeyNoncePerEpoch = args.epoch_key_per_epoch
    const circuitName = "verifyEpochKey"
    let testCircuitContent
    
    const dirPath = path.join(__dirname, '../circuits/benchmark/')
    const circomPath = path.join(__dirname, `../circuits/benchmark/${circuitName}_${date}.circom`)
    const circuitOut = path.join(__dirname, `../circuits/benchmark/${circuitName}_${date}.r1cs`)
    const wasmOut = path.join(__dirname, `../circuits/benchmark/${circuitName}_${date}.wasm`)
    const symOut = path.join(__dirname, `../circuits/benchmark/${circuitName}_${date}.sym`)
    const paramsOut = path.join(__dirname, `../circuits/benchmark/${circuitName}_${date}.params`)

    // create .circom file
    testCircuitContent = `include "../verifiyEpochKey.circom" \n\ncomponent main = verifyEpochKey(${GSTDepth}, ${epochTreeDepth}, ${epochKeyNoncePerEpoch})`

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
    const user = genIdentity()
    const proveKarmaAmount = 3
    const epochKeyNonce = 0
    const epochKey = genEpochKey(user['identityNullifier'], epoch, epochKeyNonce, epochTreeDepth)
    let minRep = null
    let reputationRecords = {}

    // Global state tree
    let GSTZERO_VALUE = 0
    const transitionedPosRep = 5
    const transitionedNegRep = 0
    const GSTree = new IncrementalQuinTree(GSTDepth, GSTZERO_VALUE, 2)
    const commitment = genIdentityCommitment(user)
    const stateRoot = genRandomSalt()
    const hashedLeaf = hash5([
        commitment, 
        stateRoot,
        BigInt(transitionedPosRep),
        BigInt(transitionedNegRep),
        BigInt(0)
    ])
    
    GSTree.insert(hashedLeaf)
    const GSTreeProof = GSTree.genMerklePath(0)
    const GSTreeRoot = GSTree.root

    const circuitInputs = {
        GST_path_elements: GSTreeProof.pathElements,
        GST_path_index: GSTreeProof.indices,
        GST_root: GSTreeRoot,
        identity_pk: user['keypair']['pubKey'],
        identity_nullifier: user['identityNullifier'], 
        identity_trapdoor: user['identityTrapdoor'],
        user_tree_root: stateRoot,
        user_state_hash: hashedLeaf,
        positive_karma: transitionedPosRep,
        negative_karma: transitionedNegRep,
        nonce: epochKeyNonce,
        epoch: epoch,
        epoch_key: epochKey,
    }

    // generate circuit proof

    const inputJsonPath = path.join(__dirname, `../circuits/benchmark/${circuitName}_${date}.input.json`)
    const witnessPath = path.join(__dirname, `../circuits/benchmark/${circuitName}_${date}.witness.wtns`)
    const witnessJsonPath = path.join(__dirname, `../circuits/benchmark/${circuitName}_${date}.witness.json`)
    const proofPath = path.join(__dirname, `../circuits/benchmark/${circuitName}_${date}.proof.json`)
    const publicJsonPath = path.join(__dirname, `../circuits/benchmark/${circuitName}_${date}.publicSignals.json`)

    fs.writeFileSync(inputJsonPath, JSON.stringify(stringifyBigInts(circuitInputs)))

    const startGenProofTime = Math.floor(new Date().getTime() )
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
