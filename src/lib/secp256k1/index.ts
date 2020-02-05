import * as _secp256k1 from 'secp256k1';

import { ISecp256k1 } from './typings';

import { randomBytes } from '../../random';
import { bufferToArray } from '../../helpers/util';

const secp256k1: ISecp256k1 = _secp256k1 as any;

export function createPrivateKey(): Buffer {
  let privateKey = randomBytes(32);
  while (!verifyPrivateKey(privateKey)) {
    privateKey = randomBytes(32);
  }
  return privateKey;
}

export function verifyPrivateKey(privateKey: Buffer): boolean {
  return secp256k1.privateKeyVerify(bufferToArray(privateKey));
}

export function createPublicKey(
  privateKey: Buffer,
  compressed: boolean = true
): Buffer {
  const result = secp256k1.publicKeyCreate(
    bufferToArray(privateKey),
    compressed
  );
  const buf = Buffer.from(result);
  return buf;
}

export function ecdsaSign(msg: Buffer, privateKey: Buffer): Buffer {
  const { signature } = secp256k1.ecdsaSign(
    bufferToArray(msg),
    bufferToArray(privateKey)
  );
  const buf = Buffer.from(signature);
  return buf;
}

export function ecdsaVerify(
  sig: Buffer,
  msg: Buffer,
  publicKey: Buffer
): boolean {
  return secp256k1.ecdsaVerify(
    bufferToArray(sig),
    bufferToArray(msg),
    bufferToArray(publicKey)
  );
}

export function ecdhDerive(publicKey: Buffer, privateKey: Buffer) {
  const result = secp256k1.ecdh(
    bufferToArray(publicKey),
    bufferToArray(privateKey)
  );
  const buf = Buffer.from(result);
  return buf;
}
