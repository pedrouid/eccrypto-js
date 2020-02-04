import { ec as EC } from 'elliptic';

import { randomBytes } from './random';
import { KeyPair } from './types';
import { assert, isValidPrivateKey } from './validators';

const secp256k1curve = new EC('secp256k1');

export function getCurve() {
  return secp256k1curve;
}

/**
 * Generate a new valid private key. Will use the window.crypto or window.msCrypto as source
 * depending on your browser.
 * @return {Buffer} A 32-byte private key.
 * @function
 */
export function generatePrivate() {
  let privateKey = randomBytes(32);
  while (!isValidPrivateKey(privateKey)) {
    privateKey = randomBytes(32);
  }
  return privateKey;
}

export function getPublic(privateKey: Buffer) {
  // This function has sync API so we throw an error immediately.
  assert(privateKey.length === 32, 'Bad private key');
  assert(isValidPrivateKey(privateKey), 'Bad private key');
  // XXX(Kagami): `elliptic.utils.encode` returns array for every
  // encoding except `hex`.
  return Buffer.from(
    secp256k1curve.keyFromPrivate(privateKey).getPublic('hex')
  );
}

/**
 * Get compressed version of public key.
 */
export function getPublicCompressed(privateKey: Buffer) {
  assert(privateKey.length === 32, 'Bad private key');
  assert(isValidPrivateKey(privateKey), 'Bad private key');
  // See https://github.com/wanderer/secp256k1-node/issues/46
  const compressed = true;
  return Buffer.from(
    secp256k1curve.keyFromPrivate(privateKey).getPublic(compressed, 'hex')
  );
}

export function generateKeyPair(): KeyPair {
  const privateKey = generatePrivate();
  const publicKey = getPublic(privateKey);
  return { privateKey, publicKey };
}

export function sign(privateKey: Buffer, msg: Buffer) {
  return new Promise(async resolve => {
    assert(privateKey.length === 32, 'Bad private key');
    assert(isValidPrivateKey(privateKey), 'Bad private key');
    assert(msg.length > 0, 'Message should not be empty');
    assert(msg.length <= 32, 'Message is too long');
    resolve(
      Buffer.from(
        secp256k1curve.sign(msg, privateKey, { canonical: true }).toDER()
      )
    );
  });
}

export function verify(publicKey: Buffer, msg: Buffer, sig: Buffer) {
  return new Promise(function(resolve, reject) {
    assert(
      publicKey.length === 65 || publicKey.length === 33,
      'Bad public key'
    );
    if (publicKey.length === 65) {
      assert(publicKey[0] === 4, 'Bad public key');
    }
    if (publicKey.length === 33) {
      assert(publicKey[0] === 2 || publicKey[0] === 3, 'Bad public key');
    }
    assert(msg.length > 0, 'Message should not be empty');
    assert(msg.length <= 32, 'Message is too long');
    if (secp256k1curve.verify(msg, sig, publicKey)) {
      resolve(null);
    } else {
      reject(new Error('Bad signature'));
    }
  });
}
