import { isNode } from './lib/node';
import {
  secp256k1GeneratePrivate,
  secp256k1GetPublic,
  secp256k1Sign,
  secp256k1Verify,
} from './lib/secp256k1';
import {
  ellipticGeneratePrivate,
  ellipticGetPublic,
  ellipticSign,
  ellipticVerify,
} from './lib/elliptic';

import { KeyPair } from './helpers/types';
import { assert, isValidPrivateKey } from './helpers/validators';

export function generatePrivate() {
  return isNode() ? secp256k1GeneratePrivate() : ellipticGeneratePrivate();
}

export function checkPrivateKey(privateKey: Buffer) {
  assert(privateKey.length === 32, 'Bad private key');
  assert(isValidPrivateKey(privateKey), 'Bad private key');
}

export function checkPublicKey(publicKey: Buffer) {
  assert(publicKey.length === 65 || publicKey.length === 33, 'Bad public key');
  if (publicKey.length === 65) {
    assert(publicKey[0] === 4, 'Bad public key');
  }
  if (publicKey.length === 33) {
    assert(publicKey[0] === 2 || publicKey[0] === 3, 'Bad public key');
  }
}

export function checkMessage(msg: Buffer) {
  assert(msg.length > 0, 'Message should not be empty');
  assert(msg.length <= 32, 'Message is too long');
}

export function getPublic(privateKey: Buffer) {
  checkPrivateKey(privateKey);
  return isNode()
    ? secp256k1GetPublic(privateKey)
    : ellipticGetPublic(privateKey);
}

export function generateKeyPair(): KeyPair {
  const privateKey = generatePrivate();
  const publicKey = getPublic(privateKey);
  return { privateKey, publicKey };
}

export async function sign(privateKey: Buffer, msg: Buffer): Promise<Buffer> {
  checkPrivateKey(privateKey);
  checkMessage(msg);
  return isNode()
    ? secp256k1Sign(msg, privateKey)
    : ellipticSign(msg, privateKey);
}

export async function verify(
  publicKey: Buffer,
  msg: Buffer,
  sig: Buffer
): Promise<null> {
  checkPublicKey(publicKey);
  checkMessage(msg);
  const sigGood = isNode()
    ? secp256k1Verify(sig, msg, publicKey)
    : ellipticVerify(sig, msg, publicKey);
  if (sigGood) {
    return null;
  } else {
    throw new Error('Bad signature');
  }
}
