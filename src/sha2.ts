import { arrayify } from '@ethersproject/bytes';
import { toUtf8Bytes } from '@ethersproject/strings';
import {
  sha256 as _sha256,
  sha512 as _sha512,
  computeHmac,
  SupportedAlgorithm,
} from '@ethersproject/sha2';

import { removeTrailing0x } from './util';
import { equalConstTime } from './validators';

export async function sha256(msg: string): Promise<string> {
  const bytes = toUtf8Bytes(msg);
  const hash = _sha256(bytes);
  return removeTrailing0x(hash);
}

export async function sha512(msg: string): Promise<string> {
  const bytes = toUtf8Bytes(msg);
  const hash = _sha512(bytes);
  return removeTrailing0x(hash);
}

export async function hashSharedKey(sharedKey: Buffer): Promise<Uint8Array> {
  const hash = _sha512(sharedKey);
  return arrayify(hash);
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
