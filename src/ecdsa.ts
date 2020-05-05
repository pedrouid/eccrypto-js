import { isNode } from './lib/env';
import {
  secp256k1GeneratePrivate,
  secp256k1GetPublic,
  secp256k1Sign,
  secp256k1Verify,
  secp256k1GetPublicCompressed,
  secp256k1Compress,
  secp256k1Decompress,
  secp256k1SignatureExport,
  secp256k1Recover,
} from './lib/secp256k1';
import {
  ellipticGeneratePrivate,
  ellipticGetPublic,
  ellipticSign,
  ellipticVerify,
  ellipticGetPublicCompressed,
  ellipticDecompress,
  ellipticCompress,
  ellipticSignatureExport,
  ellipticRecover,
} from './lib/elliptic';
import {
  KEY_LENGTH,
  MAX_MSG_LENGTH,
  PREFIXED_DECOMPRESSED_LENGTH,
  PREFIXED_KEY_LENGTH,
  ERROR_BAD_PRIVATE_KEY,
  ERROR_BAD_PUBLIC_KEY,
  ERROR_EMPTY_MESSAGE,
  ERROR_MESSAGE_TOO_LONG,
} from './constants';
import {
  KeyPair,
  assert,
  isValidPrivateKey,
  isCompressed,
  isDecompressed,
} from './helpers';

export function generatePrivate() {
  return isNode() ? secp256k1GeneratePrivate() : ellipticGeneratePrivate();
}

export function checkPrivateKey(privateKey: Buffer): void {
  assert(privateKey.length === KEY_LENGTH, ERROR_BAD_PRIVATE_KEY);
  assert(isValidPrivateKey(privateKey), ERROR_BAD_PRIVATE_KEY);
}

export function checkPublicKey(publicKey: Buffer): void {
  assert(
    publicKey.length === PREFIXED_DECOMPRESSED_LENGTH ||
      publicKey.length === PREFIXED_KEY_LENGTH,
    ERROR_BAD_PUBLIC_KEY
  );
  if (publicKey.length === PREFIXED_DECOMPRESSED_LENGTH) {
    assert(publicKey[0] === 4, ERROR_BAD_PUBLIC_KEY);
  }
  if (publicKey.length === PREFIXED_KEY_LENGTH) {
    assert(publicKey[0] === 2 || publicKey[0] === 3, ERROR_BAD_PUBLIC_KEY);
  }
}

export function checkMessage(msg: Buffer): void {
  assert(msg.length > 0, ERROR_EMPTY_MESSAGE);
  assert(msg.length <= MAX_MSG_LENGTH, ERROR_MESSAGE_TOO_LONG);
}

export function compress(publicKey: Buffer): Buffer {
  if (isCompressed(publicKey)) {
    return publicKey;
  }
  return isNode() ? secp256k1Compress(publicKey) : ellipticCompress(publicKey);
}

export function decompress(publicKey: Buffer): Buffer {
  if (isDecompressed(publicKey)) {
    return publicKey;
  }
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

export function signatureExport(sig: Buffer): Buffer {
  return isNode()
    ? secp256k1SignatureExport(sig)
    : ellipticSignatureExport(sig);
}

export function sign(privateKey: Buffer, msg: Buffer, rsvSig = false): Buffer {
  checkPrivateKey(privateKey);
  checkMessage(msg);
  return isNode()
    ? secp256k1Sign(msg, privateKey, rsvSig)
    : ellipticSign(msg, privateKey, rsvSig);
}

export function recover(msg: Buffer, sig: Buffer, compressed = false): Buffer {
  checkMessage(msg);
  return isNode()
    ? secp256k1Recover(sig, msg, compressed)
    : ellipticRecover(sig, msg, compressed);
}

export function verify(publicKey: Buffer, msg: Buffer, sig: Buffer): null {
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
