import {
  toBuffer as base64urlDecode,
  encode as base64urlEncode
} from 'base64url'
import { box, randomBytes } from 'tweetnacl'
import { TextDecoder, TextEncoder } from 'util'

export const decrypt = (privateOrSharedKey, messageWithNonce, publicKey) => {
  const messageWithNonceAsUint8Array = uint8ArrayFromBase64url(messageWithNonce)
  const nonce = messageWithNonceAsUint8Array.slice(0, box.nonceLength)
  const message = messageWithNonceAsUint8Array.slice(
    box.nonceLength,
    messageWithNonce.length
  )
  const decrypted = publicKey
    ? box.open(message, nonce, publicKey, privateOrSharedKey)
    : box.open.after(message, nonce, privateOrSharedKey)

  if (!decrypted) {
    throw new Error('Could not decrypt message')
  }

  return new TextDecoder().decode(decrypted)
}

export const encrypt = (privateOrSharedKey, data, publicKey) => {
  const nonce = newNonce()
  const messageUint8 = new TextEncoder().encode(data)
  const encrypted = publicKey
    ? box(messageUint8, nonce, publicKey, privateOrSharedKey)
    : box.after(messageUint8, nonce, privateOrSharedKey)
  const fullMessage = new Uint8Array(nonce.length + encrypted.length)

  fullMessage.set(nonce)
  fullMessage.set(encrypted, nonce.length)

  return uint8ArrayToBase64url(fullMessage)
}

export const generateKeyPair = () => box.keyPair()

const newNonce = () => randomBytes(box.nonceLength)

export const sampleTweetNaCljs = () => {
  const obj = { hello: 'world' }
  const pairA = generateKeyPair()
  const pairB = generateKeyPair()
  const sharedA = box.before(pairB.publicKey, pairA.secretKey)
  const sharedB = box.before(pairA.publicKey, pairB.secretKey)
  const encrypted = encrypt(sharedA, JSON.stringify(obj))
  const decrypted = decrypt(sharedB, encrypted)

  return {
    decrypted,
    encrypted,
    nonce: encrypted.substring(0, box.nonceLength),
    obj,
    pairA: {
      privateKey: uint8ArrayToBase64url(pairA.secretKey),
      publicKey: uint8ArrayToBase64url(pairA.publicKey)
    },
    pairB: {
      privateKey: uint8ArrayToBase64url(pairB.secretKey),
      publicKey: uint8ArrayToBase64url(pairB.publicKey)
    }
  }
}

export const uint8ArrayFromBase64url = data => {
  return new Uint8Array(base64urlDecode(data))
}

export const uint8ArrayToBase64url = data => {
  return base64urlEncode(Buffer.from(data))
}
