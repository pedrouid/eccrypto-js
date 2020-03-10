// @ts-ignore
import * as _secp256k1 from 'secp256k1';

import { ISecp256k1 } from './typings';

import { randomBytes } from '../../random';
import { ensureLength, sanitizePublicKey } from '../../helpers/util';
import { KEY_LENGTH } from '../../helpers/constants';

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
  let privateKey = randomBytes(KEY_LENGTH);
  while (!secp256k1VerifyPrivateKey(privateKey)) {
    privateKey = randomBytes(KEY_LENGTH);
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

export function secp256k1SignatureExport(sig: Buffer): Buffer {
  return secp256k1.signatureExport(sig);
}

export function secp256k1Sign(
  msg: Buffer,
  privateKey: Buffer,
  nonDER = false
): Buffer {
  const { signature } = secp256k1.sign(msg, privateKey);
  return nonDER ? signature : secp256k1SignatureExport(signature);
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
  return ensureLength(result, KEY_LENGTH);
}
