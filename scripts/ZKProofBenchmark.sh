#!/bin/bash -xe

cd "$(dirname "$0")"
cd ..

npx ts-node scripts/ZKProofBenchmark.ts -gst 4 -ust 4 -ept 4 -nt 128 -epk 4 -a 4 -k 10

echo '=======================================' &&

npx ts-node scripts/ZKProofBenchmark.ts -gst 8 -ust 8 -ept 10 -nt 64 -epk 4 -a 4 -k 10

echo '=======================================' &&

npx ts-node scripts/ZKProofBenchmark.ts -gst 9 -ust 8 -ept 10 -nt 64 -epk 4 -a 4 -k 10

echo '=======================================' &&

npx ts-node scripts/ZKProofBenchmark.ts -gst 8 -ust 9 -ept 10 -nt 64 -epk 4 -a 4 -k 10

echo '=======================================' &&

npx ts-node scripts/ZKProofBenchmark.ts -gst 8 -ust 8 -ept 11 -nt 64 -epk 4 -a 4 -k 10

echo '=======================================' &&

npx ts-node scripts/ZKProofBenchmark.ts -gst 8 -ust 8 -ept 10 -nt 64 -epk 5 -a 4 -k 10

echo '=======================================' &&

npx ts-node scripts/ZKProofBenchmark.ts -gst 8 -ust 8 -ept 10 -nt 64 -epk 4 -a 5 -k 10

echo '=======================================' 