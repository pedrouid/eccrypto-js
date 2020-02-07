import { isBrowser, browserCreateHmac } from './lib/browser';
import { fallbackCreateHmac } from './lib/fallback';
import { isNode, nodeCreateHmac } from './lib/node';

import { equalConstTime } from './helpers/validators';

export async function hmacSha256Sign(
  key: Buffer,
  msg: Buffer
): Promise<Buffer> {
  let result;
  if (isBrowser()) {
    result = await browserCreateHmac(key, msg);
  } else if (isNode()) {
    result = await nodeCreateHmac(key, msg);
  } else {
    result = await fallbackCreateHmac(key, msg);
  }
  return result;
}

export async function hmacSha256Verify(
  key: Buffer,
  msg: Buffer,
  sig: Buffer
): Promise<boolean> {
  let result;
  if (isBrowser()) {
    const expectedSig = await browserCreateHmac(key, msg);
    result = equalConstTime(expectedSig, sig);
  } else if (isNode()) {
    const expectedSig = await nodeCreateHmac(key, msg);
    result = equalConstTime(expectedSig, sig);
  } else {
    const expectedSig = await fallbackCreateHmac(key, msg);
    result = equalConstTime(expectedSig, sig);
  }
  return result;
}
