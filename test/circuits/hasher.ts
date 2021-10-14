import * as path from 'path'
import { expect } from "chai"
import { stringifyBigInts, genRandomSalt, hashLeftRight, hash5, } from "../../crypto"
import { compileAndLoadCircuit, executeCircuit, getSignalByName, } from "../../circuits/utils"

describe('Poseidon hash circuits', function (){
    this.timeout(100000)
    let circuit

    describe('Hasher5', () => {
        it('correctly hashes 5 random values', async () => {
            
            const circuitPath = path.join(__dirname, '../../circuits/test/hasher5_test.circom')
            circuit = await compileAndLoadCircuit(circuitPath)
            const preImages: any = []
            for (let i = 0; i < 5; i++) {
                preImages.push(genRandomSalt())
            }

            const circuitInputs = stringifyBigInts({
                in: preImages,
            })

            const witness = await executeCircuit(circuit, circuitInputs)
            const output = getSignalByName(circuit, witness, 'main.hash')

            const outputJS = hash5(preImages)

            expect(output.toString()).equal(outputJS.toString())
        })
    })

    describe('HashLeftRight', () => {

        it('correctly hashes two random values', async () => {
            const circuitPath = path.join(__dirname, '../../circuits/test/hashleftright_test.circom')
            const circuit = await compileAndLoadCircuit(circuitPath)

            const left = genRandomSalt()
            const right = genRandomSalt()

            const circuitInputs = stringifyBigInts({ left, right })

            const witness = await executeCircuit(circuit, circuitInputs)
            const output = getSignalByName(circuit, witness, 'main.hash')

            const outputJS = hashLeftRight(left, right)

            expect(output.toString()).equal(outputJS.toString())
        })
    })
})