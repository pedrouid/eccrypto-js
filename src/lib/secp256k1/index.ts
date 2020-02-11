// @ts-ignore
import * as _secp256k1 from 'secp256k1';

import { ISecp256k1 } from './typings';

import { randomBytes } from '../../random';
import { ensureLength, sanitizePublicKey } from '../../helpers/util';

export const secp256k1: ISecp256k1 = _secp256k1 as any;

export function secp256k1Compress(publicKey: Buffer): Buffer {
  publicKey = sanitizePublicKey(publicKey);
  return secp256k1.publicKeyConvert(publicKey, true);
}

export function secp256k1Decompress(publicKey: Buffer): Buffer {
  publicKey = sanitizePublicKey(publicKey);
  return secp256k1.publicKeyConvert(publicKey, false);
}

export function secp256k1GeneratePrivate(): Buffer {
  let privateKey = randomBytes(32);
  while (!secp256k1VerifyPrivateKey(privateKey)) {
    privateKey = randomBytes(32);
  }
  return privateKey;
}

export function secp256k1VerifyPrivateKey(privateKey: Buffer): boolean {
  return secp256k1.privateKeyVerify(privateKey);
}

export function secp256k1GetPublic(privateKey: Buffer): Buffer {
  const result = secp256k1.publicKeyCreate(privateKey, false);
  return result;
}

export function secp256k1GetPublicCompressed(privateKey: Buffer): Buffer {
  const result = secp256k1.publicKeyCreate(privateKey, true);
  return result;
}

export function secp256k1Sign(msg: Buffer, privateKey: Buffer): Buffer {
  const { signature } = secp256k1.sign(msg, privateKey);
  const result = secp256k1.signatureExport(signature);
  return result;
}

export function secp256k1Verify(
  sig: Buffer,
  msg: Buffer,
  publicKey: Buffer
): boolean {
  if (sig.length > 64) {
    sig = secp256k1.signatureImport(sig);
  }
  return secp256k1.verify(msg, sig, publicKey);
}

export function secp256k1Derive(
  publicKey: Buffer,
  privateKey: Buffer,
  compressed?: boolean
) {
  let result = secp256k1.ecdhUnsafe(publicKey, privateKey, compressed);
  return ensureLength(result, 32);
}
