import { ec as EC } from 'elliptic';

import { randomBytes } from './random';
import { KeyPair } from './types';
import { assert, isValidPrivateKey } from './validators';

const secp256k1curve = new EC('secp256k1');

export function generatePrivate() {
  let privateKey = randomBytes(32);
  while (!isValidPrivateKey(privateKey)) {
    privateKey = randomBytes(32);
  }
  return privateKey;
}

export function checkPrivateKey(privateKey: Buffer) {
  assert(privateKey.length === 32, 'Bad private key');
  assert(isValidPrivateKey(privateKey), 'Bad private key');
}

export function getPublic(privateKey: Buffer) {
  // This function has sync API so we throw an error immediately.
  checkPrivateKey(privateKey);
  // XXX(Kagami): `elliptic.utils.encode` returns array for every
  // encoding except `hex`.
  return Buffer.from(
    secp256k1curve.keyFromPrivate(privateKey).getPublic('hex'),
    'hex'
  );
}

/**
 * Get compressed version of public key.
 */
export function getPublicCompressed(privateKey: Buffer) {
  checkPrivateKey(privateKey);
  // See https://github.com/wanderer/secp256k1-node/issues/46
  const compressed = true;
  return Buffer.from(
    secp256k1curve.keyFromPrivate(privateKey).getPublic(compressed, 'hex'),
    'hex'
  );
}

export function generateKeyPair(): KeyPair {
  const privateKey = generatePrivate();
  const publicKey = getPublic(privateKey);
  return { privateKey, publicKey };
}

export function keyFromPrivate(privateKey: Buffer) {
  return secp256k1curve.keyFromPrivate(privateKey);
}

export function keyFromPublic(publicKey: Buffer) {
  return secp256k1curve.keyFromPublic(publicKey);
}

export async function sign(privateKey: Buffer, msg: Buffer): Promise<Buffer> {
  assert(privateKey.length === 32, 'Bad private key');
  assert(isValidPrivateKey(privateKey), 'Bad private key');
  assert(msg.length > 0, 'Message should not be empty');
  assert(msg.length <= 32, 'Message is too long');
  return Buffer.from(
    secp256k1curve.sign(msg, privateKey, { canonical: true }).toDER()
  );
}

export async function verify(
  publicKey: Buffer,
  msg: Buffer,
  sig: Buffer
): Promise<null> {
  assert(publicKey.length === 65 || publicKey.length === 33, 'Bad public key');
  if (publicKey.length === 65) {
    assert(publicKey[0] === 4, 'Bad public key');
  }
  if (publicKey.length === 33) {
    assert(publicKey[0] === 2 || publicKey[0] === 3, 'Bad public key');
  }
  assert(msg.length > 0, 'Message should not be empty');
  assert(msg.length <= 32, 'Message is too long');
  if (secp256k1curve.verify(msg, sig, publicKey)) {
    return null;
  } else {
    throw new Error('Bad signature');
  }
}
