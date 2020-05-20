import { execSync } from 'child_process'
import {
  decrypt, sampleTweetNaCljs, uint8ArrayFromBase64url
} from '../tweetnacl-js'
import { box } from 'tweetnacl';

const execPyNaCl = (...args) => JSON.parse(
  execSync(`python3 ../pynacl/script.py ${args.join(' ')}`)
)

describe('TweetNaCl.js tests', () => {
  test('js: bob can decrypt a box sent by alice with his private key', () => {
    const { aliceKp, bobKp, encrypted, message, nonce } = execPyNaCl('public', 'sample')
    const alicePublicKey = uint8ArrayFromBase64url(aliceKp.publicKey)
    const bobPrivateKey = uint8ArrayFromBase64url(bobKp.privateKey)
    const decrypted = decrypt(bobPrivateKey, encrypted, alicePublicKey)

    expect(decrypted).toEqual(message)
  })

  test('js: bob can decrypt a box sent by alice with his shared key', () => {
    const { aliceKp, bobKp, encrypted, message, nonce } = execPyNaCl('public', 'sample')
    const alicePublicKey = uint8ArrayFromBase64url(aliceKp.publicKey)
    const bobPrivateKey = uint8ArrayFromBase64url(bobKp.privateKey)
    const sharedB = box.before(alicePublicKey, bobPrivateKey)
    const decrypted = decrypt(sharedB, encrypted)

    expect(decrypted).toEqual(message)
  })
})

describe('PyNaCl tests', () => {
  test('python: bob can decrypt a box sent by alice with his private key', () => {
    const { encrypted, obj, pairA, pairB } = sampleTweetNaCljs()
    const alicePublicKey = pairA.publicKey
    const bobPrivateKey = pairB.privateKey
    const { decrypted } = execPyNaCl(
      'public', 'decrypt', encrypted, bobPrivateKey, alicePublicKey
    )

    expect(JSON.parse(decrypted)).toEqual(obj)
  })
})
