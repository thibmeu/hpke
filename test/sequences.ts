import it, * as test from 'node:test'

import * as HPKE from '../index.ts'

const suite = new HPKE.CipherSuite(
  HPKE.KEM_DHKEM_P256_HKDF_SHA256,
  HPKE.KDF_HKDF_SHA256,
  HPKE.AEAD_AES_128_GCM,
)

type ControlledOperation = {
  nonce: Uint8Array
  finished: Promise<void>
  succeed(): void
  fail(error: Error): void
}

function controlledAEAD(options?: { nonceLength?: number; identity?: boolean }): {
  factory: HPKE.AEADFactory
  operations: ControlledOperation[]
  enable(): void
  throwNext(error: Error): void
} {
  const implementation = HPKE.AEAD_AES_128_GCM()
  const operations: ControlledOperation[] = []
  let enabled = false
  let synchronousFailure: Error | undefined

  function control<T>(nonce: Uint8Array, run: () => Promise<T>): Promise<T> {
    if (!enabled) {
      return run()
    }
    if (synchronousFailure) {
      const failure = synchronousFailure
      synchronousFailure = undefined
      throw failure
    }

    let resolve: (() => void) | undefined
    let reject: ((error: Error) => void) | undefined
    const gate = new Promise<void>((resolveGate, rejectGate) => {
      resolve = resolveGate
      reject = rejectGate
    })
    const promise = gate.then(run)
    const finished = promise.then(
      () => undefined,
      () => undefined,
    )
    operations.push({
      nonce: new Uint8Array(nonce),
      finished,
      succeed() {
        if (!resolve) {
          throw new Error('Operation gate is unavailable')
        }
        resolve()
      },
      fail(error) {
        if (!reject) {
          throw new Error('Operation gate is unavailable')
        }
        reject(error)
      },
    })
    return promise
  }

  const factory: HPKE.AEADFactory = () => ({
    ...implementation,
    Nn: options?.nonceLength ?? implementation.Nn,
    Seal(key, nonce, aad, plaintext) {
      return control(nonce, () =>
        options?.identity
          ? Promise.resolve(new Uint8Array(plaintext))
          : implementation.Seal(key, nonce, aad, plaintext),
      )
    },
    Open(key, nonce, aad, ciphertext) {
      return control(nonce, () =>
        options?.identity
          ? Promise.resolve(new Uint8Array(ciphertext))
          : implementation.Open(key, nonce, aad, ciphertext),
      )
    },
  })

  return {
    factory,
    operations,
    enable() {
      enabled = true
    },
    throwNext(error) {
      synchronousFailure = error
    },
  }
}

function operationAt(operations: ControlledOperation[], index: number): ControlledOperation {
  const operation = operations[index]
  if (!operation) {
    throw new Error(`Missing controlled operation ${index}`)
  }
  return operation
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

  it('concurrentSeal uses distinct nonces and settles in invocation order', async (t: test.TestContext) => {
    const controlled = controlledAEAD()
    const concurrentSuite = new HPKE.CipherSuite(
      HPKE.KEM_DHKEM_P256_HKDF_SHA256,
      HPKE.KDF_HKDF_SHA256,
      controlled.factory,
    )
    const kp = await concurrentSuite.DeriveKeyPair(new Uint8Array(concurrentSuite.KEM.Nsk))
    const pkR = kp.publicKey
    const { ctx: contextS } = await concurrentSuite.SetupSender(pkR, { concurrentSeal: true })
    const aad = new Uint8Array([1, 2, 3])
    const plaintext = new Uint8Array([4, 5, 6])
    const settled: number[] = []

    controlled.enable()
    const first = contextS.Seal(plaintext, aad).then((ciphertext) => {
      settled.push(0)
      return ciphertext
    })
    const second = contextS.Seal(plaintext, aad).then((ciphertext) => {
      settled.push(1)
      return ciphertext
    })
    const firstOperation = operationAt(controlled.operations, 0)
    const secondOperation = operationAt(controlled.operations, 1)

    t.assert.notDeepStrictEqual(firstOperation.nonce, secondOperation.nonce)
    secondOperation.succeed()
    await secondOperation.finished
    t.assert.deepStrictEqual(settled, [])

    firstOperation.succeed()
    await Promise.all([first, second])
    t.assert.deepStrictEqual(settled, [0, 1])
    t.assert.strictEqual(contextS.seq, 2)
  })

  it('concurrentSeal rejects pending and later calls after a failure', async (t: test.TestContext) => {
    const controlled = controlledAEAD()
    const concurrentSuite = new HPKE.CipherSuite(
      HPKE.KEM_DHKEM_P256_HKDF_SHA256,
      HPKE.KDF_HKDF_SHA256,
      controlled.factory,
    )
    const kp = await concurrentSuite.DeriveKeyPair(new Uint8Array(concurrentSuite.KEM.Nsk))
    const { ctx } = await concurrentSuite.SetupSender(kp.publicKey, { concurrentSeal: true })
    const settled: number[] = []

    controlled.enable()
    const first = ctx.Seal(new Uint8Array([1])).catch((error: unknown) => {
      settled.push(0)
      throw error
    })
    const second = ctx.Seal(new Uint8Array([2])).catch((error: unknown) => {
      settled.push(1)
      throw error
    })
    const firstRejection = t.assert.rejects(first, /seal failed/)
    const secondRejection = t.assert.rejects(second, /Context invalidated/)
    const firstOperation = operationAt(controlled.operations, 0)
    const secondOperation = operationAt(controlled.operations, 1)

    secondOperation.succeed()
    await secondOperation.finished
    t.assert.deepStrictEqual(settled, [])

    firstOperation.fail(new Error('seal failed'))
    await Promise.all([firstRejection, secondRejection])
    t.assert.deepStrictEqual(settled, [0, 1])
    await t.assert.rejects(ctx.Seal(new Uint8Array([3])), /Context invalidated/)
    t.assert.strictEqual(controlled.operations.length, 2)
  })

  it('concurrentSeal orders synchronous AEAD failures', async (t: test.TestContext) => {
    const controlled = controlledAEAD()
    const concurrentSuite = new HPKE.CipherSuite(
      HPKE.KEM_DHKEM_P256_HKDF_SHA256,
      HPKE.KDF_HKDF_SHA256,
      controlled.factory,
    )
    const kp = await concurrentSuite.DeriveKeyPair(new Uint8Array(concurrentSuite.KEM.Nsk))
    const { ctx } = await concurrentSuite.SetupSender(kp.publicKey, { concurrentSeal: true })
    const settled: number[] = []

    controlled.enable()
    const first = ctx.Seal(new Uint8Array([1])).then(() => settled.push(0))
    controlled.throwNext(new Error('synchronous seal failure'))
    const second = ctx.Seal(new Uint8Array([2])).catch((error: unknown) => {
      settled.push(1)
      throw error
    })
    const secondRejection = t.assert.rejects(second, /synchronous seal failure/)

    await Promise.resolve()
    t.assert.deepStrictEqual(settled, [])
    operationAt(controlled.operations, 0).succeed()
    await Promise.all([first, secondRejection])
    t.assert.deepStrictEqual(settled, [0, 1])
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

  it('concurrentOpen runs concurrently and settles in invocation order', async (t: test.TestContext) => {
    const controlled = controlledAEAD()
    const concurrentSuite = new HPKE.CipherSuite(
      HPKE.KEM_DHKEM_P256_HKDF_SHA256,
      HPKE.KDF_HKDF_SHA256,
      controlled.factory,
    )
    const kp = await concurrentSuite.DeriveKeyPair(new Uint8Array(concurrentSuite.KEM.Nsk))
    const pkR = kp.publicKey
    const { encapsulatedSecret: enc, ctx: contextS } = await concurrentSuite.SetupSender(pkR)
    const contextR = await concurrentSuite.SetupRecipient(kp, enc, { concurrentOpen: true })
    const aad = new Uint8Array([1, 2, 3])
    const plaintext0 = new Uint8Array([4, 5, 6])
    const plaintext1 = new Uint8Array([7, 8, 9])
    const ciphertext0 = await contextS.Seal(plaintext0, aad)
    const ciphertext1 = await contextS.Seal(plaintext1, aad)
    const settled: number[] = []

    controlled.enable()
    const first = contextR.Open(ciphertext0, aad).then((plaintext) => {
      settled.push(0)
      return plaintext
    })
    const second = contextR.Open(ciphertext1, aad).then((plaintext) => {
      settled.push(1)
      return plaintext
    })
    const firstOperation = operationAt(controlled.operations, 0)
    const secondOperation = operationAt(controlled.operations, 1)

    t.assert.notDeepStrictEqual(firstOperation.nonce, secondOperation.nonce)
    secondOperation.succeed()
    await secondOperation.finished
    t.assert.deepStrictEqual(settled, [])

    firstOperation.succeed()
    const plaintexts = await Promise.all([first, second])
    t.assert.deepStrictEqual(plaintexts, [plaintext0, plaintext1])
    t.assert.deepStrictEqual(settled, [0, 1])
    t.assert.strictEqual(contextR.seq, 2)
  })

  it('concurrentOpen rejects pending and later calls after a failure', async (t: test.TestContext) => {
    const controlled = controlledAEAD()
    const concurrentSuite = new HPKE.CipherSuite(
      HPKE.KEM_DHKEM_P256_HKDF_SHA256,
      HPKE.KDF_HKDF_SHA256,
      controlled.factory,
    )
    const kp = await concurrentSuite.DeriveKeyPair(new Uint8Array(concurrentSuite.KEM.Nsk))
    const pkR = kp.publicKey
    const { encapsulatedSecret: enc, ctx: contextS } = await concurrentSuite.SetupSender(pkR)
    const contextR = await concurrentSuite.SetupRecipient(kp, enc, { concurrentOpen: true })
    const aad = new Uint8Array([1, 2, 3])
    const ciphertext0 = await contextS.Seal(new Uint8Array([4, 5, 6]), aad)
    const ciphertext1 = await contextS.Seal(new Uint8Array([7, 8, 9]), aad)
    const settled: number[] = []

    controlled.enable()
    const first = contextR.Open(ciphertext0, aad).catch((error: unknown) => {
      settled.push(0)
      throw error
    })
    const second = contextR.Open(ciphertext1, aad).catch((error: unknown) => {
      settled.push(1)
      throw error
    })
    const firstRejection = t.assert.rejects(first, HPKE.OpenError)
    const secondRejection = t.assert.rejects(second, HPKE.OpenError)
    const firstOperation = operationAt(controlled.operations, 0)
    const secondOperation = operationAt(controlled.operations, 1)

    secondOperation.succeed()
    await secondOperation.finished
    t.assert.deepStrictEqual(settled, [])

    firstOperation.fail(new Error('open failed'))
    await Promise.all([firstRejection, secondRejection])
    t.assert.deepStrictEqual(settled, [0, 1])
    await t.assert.rejects(contextR.Open(ciphertext1, aad), HPKE.OpenError)
    t.assert.strictEqual(controlled.operations.length, 2)
  })

  it('concurrentOpen orders synchronous AEAD failures', async (t: test.TestContext) => {
    const controlled = controlledAEAD()
    const concurrentSuite = new HPKE.CipherSuite(
      HPKE.KEM_DHKEM_P256_HKDF_SHA256,
      HPKE.KDF_HKDF_SHA256,
      controlled.factory,
    )
    const kp = await concurrentSuite.DeriveKeyPair(new Uint8Array(concurrentSuite.KEM.Nsk))
    const { encapsulatedSecret, ctx: sender } = await concurrentSuite.SetupSender(kp.publicKey)
    const recipient = await concurrentSuite.SetupRecipient(kp, encapsulatedSecret, {
      concurrentOpen: true,
    })
    const ciphertext0 = await sender.Seal(new Uint8Array([1]))
    const ciphertext1 = await sender.Seal(new Uint8Array([2]))
    const settled: number[] = []

    controlled.enable()
    const first = recipient.Open(ciphertext0).then(() => settled.push(0))
    controlled.throwNext(new Error('synchronous open failure'))
    const second = recipient.Open(ciphertext1).catch((error: unknown) => {
      settled.push(1)
      throw error
    })
    const secondRejection = t.assert.rejects(second, HPKE.OpenError)

    await Promise.resolve()
    t.assert.deepStrictEqual(settled, [])
    operationAt(controlled.operations, 0).succeed()
    await Promise.all([first, secondRejection])
    t.assert.deepStrictEqual(settled, [0, 1])
  })

  it('concurrent contexts order sequence limit errors', async (t: test.TestContext) => {
    const senderAEAD = controlledAEAD({ nonceLength: 1, identity: true })
    const senderSuite = new HPKE.CipherSuite(
      HPKE.KEM_DHKEM_P256_HKDF_SHA256,
      HPKE.KDF_HKDF_SHA256,
      senderAEAD.factory,
    )
    const senderKeyPair = await senderSuite.DeriveKeyPair(new Uint8Array(senderSuite.KEM.Nsk))
    const { ctx: sender } = await senderSuite.SetupSender(senderKeyPair.publicKey, {
      concurrentSeal: true,
    })

    senderAEAD.enable()
    const pendingSeals = Array.from({ length: 255 }, () => sender.Seal(new Uint8Array([1])))
    let senderLimitSettled = false
    const senderLimit = t.assert.rejects(
      sender.Seal(new Uint8Array([2])),
      HPKE.MessageLimitReachedError,
    )
    void senderLimit.then(() => {
      senderLimitSettled = true
    })
    await Promise.resolve()
    t.assert.strictEqual(senderLimitSettled, false)
    for (const operation of senderAEAD.operations) {
      operation.succeed()
    }
    await Promise.all([...pendingSeals, senderLimit])
    t.assert.strictEqual(senderLimitSettled, true)

    const recipientAEAD = controlledAEAD({ nonceLength: 1, identity: true })
    const recipientSuite = new HPKE.CipherSuite(
      HPKE.KEM_DHKEM_P256_HKDF_SHA256,
      HPKE.KDF_HKDF_SHA256,
      recipientAEAD.factory,
    )
    const recipientKeyPair = await recipientSuite.DeriveKeyPair(
      new Uint8Array(recipientSuite.KEM.Nsk),
    )
    const { encapsulatedSecret } = await recipientSuite.SetupSender(recipientKeyPair.publicKey)
    const recipient = await recipientSuite.SetupRecipient(recipientKeyPair, encapsulatedSecret, {
      concurrentOpen: true,
    })

    recipientAEAD.enable()
    const pendingOpens = Array.from({ length: 255 }, () => recipient.Open(new Uint8Array([1])))
    let recipientLimitSettled = false
    const recipientLimit = t.assert.rejects(
      recipient.Open(new Uint8Array([2])),
      HPKE.MessageLimitReachedError,
    )
    void recipientLimit.then(() => {
      recipientLimitSettled = true
    })
    await Promise.resolve()
    t.assert.strictEqual(recipientLimitSettled, false)
    for (const operation of recipientAEAD.operations) {
      operation.succeed()
    }
    await Promise.all([...pendingOpens, recipientLimit])
    t.assert.strictEqual(recipientLimitSettled, true)
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
