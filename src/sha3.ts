import { sha3_256, keccak_256 } from 'js-sha3';

import { hexToBuffer } from './helpers';

export function sha3(msg: Buffer): Buffer {
  return hexToBuffer(sha3_256(msg));
}

export function keccak256(msg: Buffer): Buffer {
  return hexToBuffer(keccak_256(msg));
}
