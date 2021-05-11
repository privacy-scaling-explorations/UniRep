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

import { genEpochKey, genEpochKeyNullifier, genNewEpochTreeForBenchmark, genNewNullifierTree, genNewNullifierTreeForBenchmark, genNewUserStateTree, genNewUserStateTreeForBenchmark, SMT_ONE_LEAF } from '../test/utils'
import { genRandomSalt, hash5, hashOne, IncrementalQuinTree, stringifyBigInts, unstringifyBigInts } from 'maci-crypto'

import { Reputation } from "../core"

const exec = (command: string) => {
    return shell.exec(command, { silent: true })
}


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

    parser.addArgument(
        ['-k', '--karma'],
        {
            help: 'The number of karma a user can spend per epoch',
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
    const maxKarmaBudget = args.karma

    // verify epoch key
    const verifyEpochKeyCommend = `npx ts-node scripts/verifyEpochKeyTest.ts -gst ${GSTDepth} -ept ${epochTreeDepth} -epk ${epochKeyNoncePerEpoch}`
    
    const verifyEpochKeyOutput = exec(verifyEpochKeyCommend).stdout.trim()

    console.log(verifyEpochKeyCommend)
    console.log(verifyEpochKeyOutput)

    // prove reputation
    const proveReputationCommend = `npx ts-node scripts/proveReputationTest.ts -gst ${GSTDepth} -ust ${USTDepth} -ept ${epochTreeDepth} -nt ${nullifierTreeDepth} -epk ${epochKeyNoncePerEpoch} -a ${attestationNum} -k ${maxKarmaBudget}`
    
    const proveReputationOutput = exec(proveReputationCommend).stdout.trim()

    console.log(proveReputationCommend)
    console.log(proveReputationOutput)

    // prove reputation From Attester
    const proveReputationFromAttesterCommend = `npx ts-node scripts/proveReputationFromAttesterTest.ts -gst ${GSTDepth} -ust ${USTDepth} -nt ${nullifierTreeDepth} -epk ${epochKeyNoncePerEpoch} `
    
    const proveReputationFromAttesterOutput = exec(proveReputationFromAttesterCommend).stdout.trim()

    console.log(proveReputationFromAttesterCommend)
    console.log(proveReputationFromAttesterOutput)
    
    // user state transition
    const userStateTransitionCommend = `npx ts-node scripts/userStateTransitionTest.ts -gst ${GSTDepth} -ust ${USTDepth} -ept ${epochTreeDepth} -nt ${nullifierTreeDepth} -epk ${epochKeyNoncePerEpoch} -a ${attestationNum}`
    
    const userStateTransitionOutput = exec(userStateTransitionCommend).stdout.trim()

    console.log(userStateTransitionCommend)
    console.log(userStateTransitionOutput)
    
    return 0;
})();
