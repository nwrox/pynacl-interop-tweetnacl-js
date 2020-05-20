import json
from sys import argv
from nacl.public import Box, PrivateKey, PublicKey
from nacl.utils import random
from nacl.encoding import URLSafeBase64Encoder

def base64url_decode(string):
    return URLSafeBase64Encoder.decode(fix_base64url_decode(string))

def base64url_encode(data):
    return fix_base64url_encode(URLSafeBase64Encoder.encode(data))

def decrypt(cipher, privateKey, publicKey):
    box = Box(privateKey, publicKey)
    cipher_raw = base64url_decode(cipher)

    return box.decrypt(cipher_raw) \
        .decode('utf-8')

def encrypt(message, privateKey, publicKey):
    box = Box(privateKey, publicKey)
    cipher_raw = box.encrypt(bytes(message, 'utf-8'), random(Box.NONCE_SIZE))
    nonce = cipher_raw[0:Box.NONCE_SIZE]

    return base64url_encode(cipher_raw), nonce

def export_keypair(keypair):
    encoder=URLSafeBase64Encoder
    privateKey = keypair['privateKey']
    publicKey = keypair['publicKey']

    return {
        'privateKey': fix_base64url_encode(privateKey.encode(encoder)),
        'publicKey': fix_base64url_encode(publicKey.encode(encoder))
    }


def fix_base64url_decode(string):
    return string + ('=' * (4 - (len(string) % 4)))

def fix_base64url_encode(bytes):
    return str(bytes, 'utf-8').rstrip('=')

def generate_keypair():
    privateKey = PrivateKey.generate()
    publicKey = privateKey.public_key

    return {
        'privateKey': privateKey,
        'publicKey': publicKey
    }

def main():
    if argv[1] == 'public' and argv[2] == 'sample':
        aliceKp = generate_keypair()
        alicePrivateKey = aliceKp['privateKey']
        alicePublicKey = aliceKp['publicKey']
        bobKp = generate_keypair()
        bobPrivateKey = bobKp['privateKey']
        bobPublicKey = bobKp['publicKey']
        message = 'Hello World!'
        cipher, nonce = encrypt(message, alicePrivateKey, bobPublicKey)

        data = {}
        data['aliceKp'] = export_keypair(aliceKp)
        data['bobKp'] = export_keypair(bobKp)
        data['encrypted'] = cipher
        data['decrypted'] = decrypt(cipher, bobPrivateKey, alicePublicKey)
        data['message'] = message
        data['nonce'] = base64url_encode(nonce)

        print(json.dumps(data, indent=2))

    if argv[1] == 'public' and argv[2] == 'decrypt':
        encoder=URLSafeBase64Encoder
        alicePublicKey = PublicKey(fix_base64url_decode(argv[5]), encoder)
        bobPrivateKey = PrivateKey(fix_base64url_decode(argv[4]), encoder)
        cipher = argv[3]

        data = {}
        data['decrypted'] = decrypt(cipher, bobPrivateKey, alicePublicKey)

        print(json.dumps(data, indent=2))

if __name__ == '__main__':
    main()
