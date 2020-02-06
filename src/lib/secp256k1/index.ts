// @ts-ignore
import * as _secp256k1 from 'secp256k1';

import { ISecp256k1 } from './typings';

import { randomBytes } from '../../random';

const secp256k1: ISecp256k1 = _secp256k1 as any;

function ensureLength(data: Buffer, expectedLength: number) {
  const diff = data.length - expectedLength;
  if (diff > 0) {
    data = data.slice(diff);
  }
  return data;
}

export function createPrivateKey(): Buffer {
  let privateKey = randomBytes(32);
  while (!verifyPrivateKey(privateKey)) {
    privateKey = randomBytes(32);
  }
  return privateKey;
}

export function verifyPrivateKey(privateKey: Buffer): boolean {
  return secp256k1.privateKeyVerify(privateKey);
}

export function createPublicKey(
  privateKey: Buffer,
  compressed?: boolean
): Buffer {
  const result = secp256k1.publicKeyCreate(privateKey, compressed);
  return result;
}

export function ecdsaSign(msg: Buffer, privateKey: Buffer): Buffer {
  const { signature } = secp256k1.sign(msg, privateKey);
  const result = secp256k1.signatureExport(signature);
  return result;
}

export function ecdsaVerify(
  sig: Buffer,
  msg: Buffer,
  publicKey: Buffer
): boolean {
  if (sig.length > 64) {
    sig = secp256k1.signatureImport(sig);
  }
  return secp256k1.verify(msg, sig, publicKey);
}

export function ecdhDerive(
  publicKey: Buffer,
  privateKey: Buffer,
  compressed?: boolean
) {
  let result = secp256k1.ecdhUnsafe(publicKey, privateKey, compressed);
  return ensureLength(result, 32);
}
