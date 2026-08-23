import { performance } from 'node:perf_hooks'
import * as HPKE from '../index.js'

const batch = 64
const width = 4
const samples = Number.parseInt(process.env.BENCH_SAMPLES ?? '25', 10)
const sizes = [1024, 16 * 1024]
const modes = [undefined, 'concurrent-fail-stop']

if (!Number.isInteger(samples) || samples < 1) {
  throw new TypeError('BENCH_SAMPLES must be a positive integer')
}

const suite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  HPKE.KDF_HKDF_SHA256,
  HPKE.AEAD_AES_128_GCM,
)

async function inWaves(values, operation) {
  const output = []
  for (let offset = 0; offset < values.length; offset += width) {
    output.push(...(await Promise.all(values.slice(offset, offset + width).map(operation))))
  }
  return output
}

async function contexts(operationMode) {
  const keyPair = await suite.GenerateKeyPair()
  const { encapsulatedSecret, ctx: sender } = await suite.SetupSender(keyPair.publicKey, {
    operationMode,
  })
  const recipient = await suite.SetupRecipient(keyPair, encapsulatedSecret, { operationMode })
  return { sender, recipient }
}

async function caseFactory(operation, operationMode, plaintexts) {
  const { sender, recipient } = await contexts(operationMode)
  if (operation === 'Seal') {
    return () => inWaves(plaintexts, (plaintext) => sender.Seal(plaintext))
  }
  const ciphertexts = []
  for (const plaintext of plaintexts) ciphertexts.push(await sender.Seal(plaintext))
  return () => inWaves(ciphertexts, (ciphertext) => recipient.Open(ciphertext))
}

async function measure(factory) {
  await (
    await factory()
  )()
  const timings = []
  for (let sample = 0; sample < samples; sample++) {
    const run = await factory()
    const start = performance.now()
    await run()
    timings.push(performance.now() - start)
  }
  return timings.toSorted((a, b) => a - b)[Math.floor(timings.length / 2)]
}

console.log(
  `Node ${process.version}; ${batch} messages; concurrency ${width}; median of ${samples}`,
)
console.log('size\toperation\tserialized\tconcurrent\tspeedup')

for (const size of sizes) {
  const plaintexts = Array.from({ length: batch }, (_, index) => {
    const plaintext = new Uint8Array(size)
    plaintext.fill(index)
    return plaintext
  })
  for (const operation of ['Seal', 'Open']) {
    const timings = {}
    for (const mode of modes) {
      timings[mode ?? 'serialized'] = await measure(() => caseFactory(operation, mode, plaintexts))
    }
    const speedup = timings.serialized / timings['concurrent-fail-stop']
    console.log(
      `${size / 1024} KiB\t${operation}\t${timings.serialized.toFixed(2)} ms\t${timings['concurrent-fail-stop'].toFixed(2)} ms\t${speedup.toFixed(2)}x`,
    )
  }
}
