import { isNode } from './lib/node';
import {
  secp256k1GeneratePrivate,
  secp256k1GetPublic,
  secp256k1Sign,
  secp256k1Verify,
  secp256k1GetPublicCompressed,
  secp256k1Compress,
  secp256k1Decompress,
} from './lib/secp256k1';
import {
  ellipticGeneratePrivate,
  ellipticGetPublic,
  ellipticSign,
  ellipticVerify,
  ellipticGetPublicCompressed,
  ellipticDecompress,
  ellipticCompress,
} from './lib/elliptic';

import { KeyPair } from './helpers/types';
import { assert, isValidPrivateKey } from './helpers/validators';
import {
  KEY_LENGTH,
  MAX_MSG_LENGTH,
  PREFIXED_DECOMPRESSED_LENGTH,
  PREFIXED_KEY_LENGTH,
} from './helpers/constants';

export function generatePrivate() {
  return isNode() ? secp256k1GeneratePrivate() : ellipticGeneratePrivate();
}

export function checkPrivateKey(privateKey: Buffer): void {
  assert(privateKey.length === KEY_LENGTH, 'Bad private key');
  assert(isValidPrivateKey(privateKey), 'Bad private key');
}

export function checkPublicKey(publicKey: Buffer): void {
  assert(
    publicKey.length === PREFIXED_DECOMPRESSED_LENGTH ||
      publicKey.length === PREFIXED_KEY_LENGTH,
    'Bad public key'
  );
  if (publicKey.length === PREFIXED_DECOMPRESSED_LENGTH) {
    assert(publicKey[0] === 4, 'Bad public key');
  }
  if (publicKey.length === PREFIXED_KEY_LENGTH) {
    assert(publicKey[0] === 2 || publicKey[0] === 3, 'Bad public key');
  }
}

export function checkMessage(msg: Buffer): void {
  assert(msg.length > 0, 'Message should not be empty');
  assert(msg.length <= MAX_MSG_LENGTH, 'Message is too long');
}

export function compress(publicKey: Buffer): Buffer {
  return isNode() ? secp256k1Compress(publicKey) : ellipticCompress(publicKey);
}

export function decompress(publicKey: Buffer): Buffer {
  return isNode()
    ? secp256k1Decompress(publicKey)
    : ellipticDecompress(publicKey);
}

export function getPublic(privateKey: Buffer) {
  checkPrivateKey(privateKey);
  return isNode()
    ? secp256k1GetPublic(privateKey)
    : ellipticGetPublic(privateKey);
}

export function getPublicCompressed(privateKey: Buffer) {
  checkPrivateKey(privateKey);
  return isNode()
    ? secp256k1GetPublicCompressed(privateKey)
    : ellipticGetPublicCompressed(privateKey);
}

export function generateKeyPair(): KeyPair {
  const privateKey = generatePrivate();
  const publicKey = getPublic(privateKey);
  return { privateKey, publicKey };
}

export async function sign(
  privateKey: Buffer,
  msg: Buffer,
  noDER?: boolean
): Promise<Buffer> {
  checkPrivateKey(privateKey);
  checkMessage(msg);
  return isNode()
    ? secp256k1Sign(msg, privateKey, noDER)
    : ellipticSign(msg, privateKey, noDER);
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
