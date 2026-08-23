import it, * as test from 'node:test'

import * as HPKE from '../index.ts'

const suite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  HPKE.KDF_HKDF_SHA256,
  HPKE.AEAD_AES_128_GCM,
)

function controlledOpen() {
  const implementation = HPKE.AEAD_AES_128_GCM()
  const operations: Array<{ succeed(): void }> = []
  let enabled = false

  const factory: HPKE.AEADFactory = () => ({
    ...implementation,
    Open(key, nonce, aad, ciphertext) {
      if (!enabled) {
        return implementation.Open(key, nonce, aad, ciphertext)
      }
      let succeed!: () => void
      const gate = new Promise<void>((resolve) => {
        succeed = resolve
      })
      operations.push({ succeed })
      return gate.then(() => new Uint8Array(ciphertext))
    },
  })

  return { factory, operations, enable: () => (enabled = true) }
}

test.describe('IncrementSeq', () => {
  it('Context seq is 0 before first message and 1 after it', async (t: test.TestContext) => {
    const kp = await suite.DeriveKeyPair(
      new Uint8Array(suite.KEM.Nsk),
      // @ts-expect-error
      typeof crypto.subtle.getPublicKey !== 'function',
    )
    const pkR = kp.publicKey
    const skR = kp.privateKey

    const { encapsulatedSecret: enc, ctx: contextS } = await suite.SetupSender(pkR)
    const contextR = await suite.SetupRecipient(skR, enc)

    // Check that seq is 0 before first message
    t.assert.strictEqual(contextS.seq, 0)
    t.assert.strictEqual(contextR.seq, 0)

    // Send first message
    const aad = new Uint8Array([1, 2, 3])
    const pt = new Uint8Array([4, 5, 6])
    const ct = await contextS.Seal(pt, aad)
    await contextR.Open(ct, aad)

    // Check that seq is 1 after first message
    t.assert.strictEqual(contextS.seq, 1)
    t.assert.strictEqual(contextR.seq, 1)
  })

  it('concurrent-fail-stop processes overlapping messages with distinct nonces', async (t: test.TestContext) => {
    const kp = await suite.DeriveKeyPair(new Uint8Array(suite.KEM.Nsk))
    const pkR = kp.publicKey

    const { encapsulatedSecret: enc, ctx: contextS } = await suite.SetupSender(pkR, {
      operationMode: 'concurrent-fail-stop',
    })
    const contextR = await suite.SetupRecipient(kp, enc, { operationMode: 'concurrent-fail-stop' })

    const aad = new Uint8Array([1, 2, 3])
    const plaintexts = Array.from({ length: 4 }, (_, i) => new Uint8Array([i]))
    const sealPromises = plaintexts.map((pt) => contextS.Seal(pt, aad))
    const ciphertexts = await Promise.all(sealPromises)

    t.assert.strictEqual(contextS.seq, plaintexts.length)
    for (let i = 0; i < plaintexts.length; i++) {
      const decrypted = await contextR.Open(ciphertexts[i]!, aad)
      t.assert.deepStrictEqual(decrypted, plaintexts[i])
    }
  })

  it('Failed Open() does not increment sequence number', async (t: test.TestContext) => {
    const kp = await suite.DeriveKeyPair(
      new Uint8Array(suite.KEM.Nsk),
      // @ts-expect-error
      typeof crypto.subtle.getPublicKey !== 'function',
    )
    const pkR = kp.publicKey
    const skR = kp.privateKey

    const { encapsulatedSecret: enc, ctx: contextS } = await suite.SetupSender(pkR)
    const contextR = await suite.SetupRecipient(skR, enc)

    const aad = new Uint8Array([1, 2, 3])
    const pt = new Uint8Array([4, 5, 6])
    const ct = await contextS.Seal(pt, aad)

    // Verify seq is 0
    t.assert.strictEqual(contextR.seq, 0)

    // Tamper with the ciphertext
    const badCt = new Uint8Array(ct)
    badCt[0]! ^= 0xff

    // Attempt to open with bad ciphertext - should fail
    await t.assert.rejects(contextR.Open(badCt, aad), HPKE.OpenError)

    // Sequence number should still be 0
    t.assert.strictEqual(contextR.seq, 0)

    // Now open with the correct ciphertext - should succeed
    const decrypted = await contextR.Open(ct, aad)
    t.assert.deepStrictEqual(decrypted, pt)

    // Now sequence should be 1
    t.assert.strictEqual(contextR.seq, 1)
  })

  it('concurrent-fail-stop settles promises in invocation order', async (t: test.TestContext) => {
    const controlled = controlledOpen()
    const controlledSuite = new HPKE.CipherSuite(
      HPKE.KEM_DHKEM_P256_HKDF_SHA256,
      HPKE.KDF_HKDF_SHA256,
      controlled.factory,
    )
    const kp = await controlledSuite.DeriveKeyPair(new Uint8Array(controlledSuite.KEM.Nsk))
    const { encapsulatedSecret, ctx: sender } = await controlledSuite.SetupSender(kp.publicKey)
    const recipient = await controlledSuite.SetupRecipient(kp, encapsulatedSecret, {
      operationMode: 'concurrent-fail-stop',
    })
    const ciphertexts = await Promise.all([
      sender.Seal(new Uint8Array([0])),
      sender.Seal(new Uint8Array([1])),
    ])
    const settled: number[] = []

    controlled.enable()
    const opens = ciphertexts.map((ciphertext, index) =>
      recipient.Open(ciphertext).then(() => settled.push(index)),
    )
    await Promise.resolve()

    controlled.operations[1]!.succeed()
    await Promise.resolve()
    t.assert.deepStrictEqual(settled, [])

    controlled.operations[0]!.succeed()
    await Promise.all(opens)
    t.assert.deepStrictEqual(settled, [0, 1])
  })

  it('concurrent-fail-stop invalidates pending and later operations after a failure', async (t: test.TestContext) => {
    const kp = await suite.DeriveKeyPair(new Uint8Array(suite.KEM.Nsk))
    const pkR = kp.publicKey

    const { encapsulatedSecret: enc, ctx: contextS } = await suite.SetupSender(pkR)
    const contextR = await suite.SetupRecipient(kp, enc, { operationMode: 'concurrent-fail-stop' })

    const aad = new Uint8Array([1, 2, 3])
    const ct0 = await contextS.Seal(new Uint8Array([4, 5, 6]), aad)
    const ct1 = await contextS.Seal(new Uint8Array([7, 8, 9]), aad)

    const badCt = new Uint8Array(ct0)
    badCt[0]! ^= 0xff

    await Promise.all([
      t.assert.rejects(contextR.Open(badCt, aad), HPKE.OpenError),
      t.assert.rejects(contextR.Open(ct1, aad), HPKE.OpenError),
    ])
    await t.assert.rejects(contextR.Open(ct1, aad), HPKE.OpenError)
  })

  it('Export() does not increment sequence number', async (t: test.TestContext) => {
    const kp = await suite.DeriveKeyPair(
      new Uint8Array(suite.KEM.Nsk),
      // @ts-expect-error
      typeof crypto.subtle.getPublicKey !== 'function',
    )
    const pkR = kp.publicKey
    const skR = kp.privateKey

    const { encapsulatedSecret: enc, ctx: contextS } = await suite.SetupSender(pkR)
    const contextR = await suite.SetupRecipient(skR, enc)

    // Verify initial sequence is 0
    t.assert.strictEqual(contextS.seq, 0)
    t.assert.strictEqual(contextR.seq, 0)

    // Export from sender context
    const exporterContext = new Uint8Array([7, 8, 9])
    const exportedS1 = await contextS.Export(exporterContext, 32)
    t.assert.strictEqual(exportedS1.byteLength, 32)

    // Sequence should still be 0
    t.assert.strictEqual(contextS.seq, 0)

    // Export from recipient context
    const exportedR1 = await contextR.Export(exporterContext, 32)
    t.assert.strictEqual(exportedR1.byteLength, 32)

    // Sequence should still be 0
    t.assert.strictEqual(contextR.seq, 0)
  })
})
