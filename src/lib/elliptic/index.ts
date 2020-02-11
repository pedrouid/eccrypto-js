import { ec as EC } from 'elliptic';

import { randomBytes } from '../../random';
import { isValidPrivateKey } from '../../helpers/validators';
import { sanitizePublicKey } from '../../helpers/util';

const ec = new EC('secp256k1');

export function ellipticCompress(publicKey: Buffer): Buffer {
  publicKey = sanitizePublicKey(publicKey);
  const pubPoint = ec.keyFromPublic(publicKey);
  const hex = pubPoint.getPublic().encode('hex', true);
  return Buffer.from(hex, 'hex');
}

export function ellipticDecompress(publicKey: Buffer): Buffer {
  publicKey = sanitizePublicKey(publicKey);
  const pubPoint = ec.keyFromPublic(publicKey);
  const hex = pubPoint.getPublic().encode('hex', false);
  return Buffer.from(hex, 'hex');
}

export function ellipticGeneratePrivate(): Buffer {
  let privateKey = randomBytes(32);
  while (!ellipticVerifyPrivateKey(privateKey)) {
    privateKey = randomBytes(32);
  }
  return privateKey;
}

export function ellipticVerifyPrivateKey(privateKey: Buffer): boolean {
  return isValidPrivateKey(privateKey);
}

export function ellipticGetPublic(privateKey: Buffer): Buffer {
  return Buffer.from(
    ec.keyFromPrivate(privateKey).getPublic(false, 'hex'),
    'hex'
  );
}

export function ellipticGetPublicCompressed(privateKey: Buffer): Buffer {
  return Buffer.from(
    ec.keyFromPrivate(privateKey).getPublic(true, 'hex'),
    'hex'
  );
}

export function ellipticDerive(publicKeyB: Buffer, privateKeyA: Buffer) {
  const keyA = ec.keyFromPrivate(privateKeyA);
  const keyB = ec.keyFromPublic(publicKeyB);
  const Px = keyA.derive(keyB.getPublic());
  return Buffer.from(Px.toArray());
}

export function ellipticSign(msg: Buffer, privateKey: Buffer): Buffer {
  return Buffer.from(ec.sign(msg, privateKey, { canonical: true }).toDER());
}

export function ellipticVerify(
  sig: Buffer,
  msg: Buffer,
  publicKey: Buffer
): boolean {
  return ec.verify(msg, sig, publicKey);
}
