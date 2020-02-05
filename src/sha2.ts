import { arrayify, isHexString } from '@ethersproject/bytes';
import {
  sha256 as _sha256,
  sha512 as _sha512,
  computeHmac,
  SupportedAlgorithm,
} from '@ethersproject/sha2';

import { equalConstTime } from './validators';

export async function sha256(msg: Buffer | string): Promise<Buffer> {
  const enc = isHexString(msg) ? 'hex' : undefined;
  const buf = typeof msg === 'string' ? Buffer.from(msg, enc) : msg;
  const hash = _sha256(buf);
  return Buffer.from(arrayify(hash));
}

export async function sha512(msg: Buffer | string): Promise<Buffer> {
  const enc = isHexString(msg) ? 'hex' : undefined;
  const buf = typeof msg === 'string' ? Buffer.from(msg, enc) : msg;
  const hash = _sha512(buf);
  return Buffer.from(arrayify(hash));
}

export async function hmacSha256Sign(
  key: Buffer,
  msg: Buffer
): Promise<Buffer> {
  const result = computeHmac(SupportedAlgorithm.sha256, key, msg);
  return Buffer.from(result);
}

export async function hmacSha256Verify(
  key: Buffer,
  msg: Buffer,
  sig: Buffer
): Promise<boolean> {
  const expectedSig = await hmacSha256Sign(key, msg);
  return equalConstTime(expectedSig, sig);
}
