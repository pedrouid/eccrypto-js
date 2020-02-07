import { sha3_256, keccak_256 } from 'js-sha3';

import { prepareHash } from './helpers/util';

export function sha3(msg: Buffer | string): Buffer {
  const buf = prepareHash(msg);
  return Buffer.from(sha3_256(buf), 'hex');
}

export function keccak256(msg: Buffer | string): Buffer {
  const buf = prepareHash(msg);
  return Buffer.from(keccak_256(buf), 'hex');
}
