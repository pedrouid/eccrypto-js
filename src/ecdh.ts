import { isNode } from './helpers';
import { secp256k1Derive } from './lib';
import { ellipticDerive } from './lib';

import { checkPrivateKey, checkPublicKey } from './helpers';

export function derive(privateKeyA: Buffer, publicKeyB: Buffer): Buffer {
  checkPrivateKey(privateKeyA);
  checkPublicKey(publicKeyB);
  return isNode()
    ? secp256k1Derive(publicKeyB, privateKeyA)
    : ellipticDerive(publicKeyB, privateKeyA);
}
