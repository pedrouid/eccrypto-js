import { toUtf8Bytes } from '@ethersproject/strings';
import { arrayify } from '@ethersproject/bytes';
import {
  sha256 as _sha256,
  sha512 as _sha512,
  computeHmac,
  SupportedAlgorithm,
} from '@ethersproject/sha2';

import { equalConstTime } from './validators';

export function sha256(msg: string): Promise<Uint8Array> {
  return new Promise(async resolve => {
    const bytes = toUtf8Bytes(msg);
    const hash = _sha256(bytes);
    resolve(arrayify(hash));
  });
}

export function sha512(msg: string): Promise<Uint8Array> {
  return new Promise(async resolve => {
    const bytes = toUtf8Bytes(msg);
    const hash = _sha512(bytes);
    resolve(arrayify(hash));
  });
}

export function hmacSha256Sign(key: Buffer, msg: Buffer): Promise<Buffer> {
  return new Promise(async resolve => {
    const result = computeHmac(SupportedAlgorithm.sha256, key, msg);
    resolve(Buffer.from(result));
  });
}

export function hmacSha256Verify(
  key: Buffer,
  msg: Buffer,
  sig: Buffer
): Promise<boolean> {
  return new Promise(async resolve => {
    const expectedSig = await hmacSha256Sign(key, msg);
    resolve(equalConstTime(expectedSig, sig));
  });
}
