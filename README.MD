# Unirep
UniRep is a private and nonrepudiable repuation system. Users can receive positive and negative reputation from attesters, and voluntarily prove that they have at least certain amount of reputation without revealing the exact amount. Moreover, users cannot refuse to receive reputation from an attester.

For more information, refer to the [documentation](https://vivi432.gitbook.io/unirep/)

## Install and build

```
npm install
```

then run

```
npm run build
``` 
to build the circuits

## Test
Test all cli commands
```
npm run test-cli
```

Integration test
```
npm run test
```

## Benchmark test
```
npm run benchmark
```
to run benchmark [scripts](https://github.com/vivianjeng/UniRep/blob/benchmark/scripts/ZKProofBenchmark.sh)

```
npx ts-node scripts/ZKProofBenchmark.ts -gst 4 -ust 4 -ept 4 -nt 128 -epk 4 -a 6 -k 10
```
to run a single benchmark test. where 
- `-gst`: global state tree depth
- `-ust`: user state tree depth
- `ept`: epoch tree depth
- `nt`: nullifier tree depth
- `epk`: number of epoch key nonce per epoch
- `a`: attestations per epoch key
- `k`: reputation budget that a user can spend per epoch

Benchmark results can refer to [this sheet](https://docs.google.com/spreadsheets/d/1X7IZnTtKii-eNQ6TGMJ5M7CNSVSDLq_2ebJ5MtcpZMk/edit?usp=sharing)