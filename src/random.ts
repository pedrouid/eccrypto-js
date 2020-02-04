import { randomBytes as _randomBytes } from '@ethersproject/random';

export function randomBytes(size: number): Buffer {
  const arr = _randomBytes(size);
  return Buffer.from(arr);
}
