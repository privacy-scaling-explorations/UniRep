#!/bin/bash -xe

cd "$(dirname "$0")"
cd ..

npx ts-node scripts/ZKProofBenchmark.ts -gst 4 -ust 4 -ept 4 -nt 128 -epk 4 -a 10 -k 10

echo '=======================================' &&

npx ts-node scripts/ZKProofBenchmark.ts -gst 8 -ust 8 -ept 8 -nt 128 -epk 8 -a 10 -k 10

echo '=======================================' &&

npx ts-node scripts/ZKProofBenchmark.ts -gst 16 -ust 16 -ept 16 -nt 128 -epk 16 -a 10 -k 10

echo '=======================================' &&

npx ts-node scripts/ZKProofBenchmark.ts -gst 64 -ust 64 -ept 64 -nt 128 -epk 64 -a 16 -k 16

echo '=======================================' &&

npx ts-node scripts/ZKProofBenchmark.ts -gst 64 -ust 64 -ept 64 -nt 128 -epk 64 -a 32 -k 32

echo '=======================================' &&

npx ts-node scripts/ZKProofBenchmark.ts -gst 64 -ust 64 -ept 64 -nt 128 -epk 64 -a 64 -k 64

echo '=======================================' &&

npx ts-node scripts/ZKProofBenchmark.ts -gst 64 -ust 64 -ept 64 -nt 128 -epk 64 -a 128 -k 128

echo '=======================================' 