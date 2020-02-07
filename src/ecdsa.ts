import {
  createPrivateKey,
  createPublicKey,
  ecdsaSign,
  ecdsaVerify,
} from './lib/secp256k1';

import { KeyPair } from './helpers/types';
import { assert, isValidPrivateKey } from './helpers/validators';

export function generatePrivate() {
  return createPrivateKey();
}

export function checkPrivateKey(privateKey: Buffer) {
  assert(privateKey.length === 32, 'Bad private key');
  assert(isValidPrivateKey(privateKey), 'Bad private key');
}

export function getPublic(privateKey: Buffer) {
  checkPrivateKey(privateKey);
  return createPublicKey(privateKey);
}

export function getPublicCompressed(privateKey: Buffer) {
  checkPrivateKey(privateKey);
  return createPublicKey(privateKey, true);
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
