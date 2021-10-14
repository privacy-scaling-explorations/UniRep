#!/bin/bash

set -e

cd "$(dirname "$0")"
cd ..
mkdir -p build

NODE_OPTIONS=--max-old-space-size=8192 npx ts-node scripts/buildSnarks.ts -i circuits/test/proveUserSignUp_test.circom -j build/proveUserSignUpCircuit.r1cs -w build/proveUserSignUp.wasm -y build/proveUserSignUp.sym -pt build/powersOfTau28_hez_final_17.ptau -zk build/proveUserSignUp.zkey -vk build/proveUserSignUp.vkey.json