import { arrayify, isHexString } from '@ethersproject/bytes';
import { sha256 as _sha256, sha512 as _sha512 } from '@ethersproject/sha2';

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
