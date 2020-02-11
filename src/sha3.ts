import { sha3_256, keccak_256 } from 'js-sha3';

import { prepareHash, hexToBuffer } from './helpers/util';

export function sha3(msg: Buffer | string): Buffer {
  const buf = prepareHash(msg);
  return hexToBuffer(sha3_256(buf));
}

export function keccak256(msg: Buffer | string): Buffer {
  const buf = prepareHash(msg);
  return hexToBuffer(keccak_256(buf));
}
