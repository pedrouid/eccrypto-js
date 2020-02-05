import { KeyPair } from './types';
import { assert, isValidPrivateKey } from './validators';
import {
  createPrivateKey,
  createPublicKey,
  ecdsaSign,
  ecdsaVerify,
} from './secp256k1';

export function generatePrivate() {
  return createPrivateKey();
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
  return createPublicKey(privateKey, false);
}

/**
 * Get compressed version of public key.
 */
export function getPublicCompressed(privateKey: Buffer) {
  checkPrivateKey(privateKey);
  return createPublicKey(privateKey);
}

export function generateKeyPair(): KeyPair {
  const privateKey = generatePrivate();
  const publicKey = getPublic(privateKey);
  return { privateKey, publicKey };
}

export async function sign(privateKey: Buffer, msg: Buffer): Promise<Buffer> {
  assert(privateKey.length === 32, 'Bad private key');
  assert(isValidPrivateKey(privateKey), 'Bad private key');
  assert(msg.length > 0, 'Message should not be empty');
  assert(msg.length <= 32, 'Message is too long');
  return ecdsaSign(msg, privateKey);
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
  if (ecdsaVerify(sig, msg, publicKey)) {
    return null;
  } else {
    throw new Error('Bad signature');
  }
}
