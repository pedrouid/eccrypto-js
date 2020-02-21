import {
  isBrowser,
  browserHmacSha256Sign,
  browserHmacSha512Sign,
} from './lib/browser';
import { fallbackHmacSha256Sign, fallbackHmacSha512Sign } from './lib/fallback';
import { isNode, nodeHmacSha256Sign, nodeHmacSha512Sign } from './lib/node';

import { equalConstTime } from './helpers/validators';

export async function hmacSha256Sign(
  key: Buffer,
  msg: Buffer
): Promise<Buffer> {
  let result;
  if (isBrowser()) {
    result = await browserHmacSha256Sign(key, msg);
  } else if (isNode()) {
    result = nodeHmacSha256Sign(key, msg);
  } else {
    result = fallbackHmacSha256Sign(key, msg);
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
    const expectedSig = await browserHmacSha256Sign(key, msg);
    result = equalConstTime(expectedSig, sig);
  } else if (isNode()) {
    const expectedSig = nodeHmacSha256Sign(key, msg);
    result = equalConstTime(expectedSig, sig);
  } else {
    const expectedSig = fallbackHmacSha256Sign(key, msg);
    result = equalConstTime(expectedSig, sig);
  }
  return result;
}

export async function hmacSha512Sign(
  key: Buffer,
  msg: Buffer
): Promise<Buffer> {
  let result;
  if (isBrowser()) {
    result = await browserHmacSha512Sign(key, msg);
  } else if (isNode()) {
    result = nodeHmacSha512Sign(key, msg);
  } else {
    result = fallbackHmacSha512Sign(key, msg);
  }
  return result;
}

export async function hmacSha512Verify(
  key: Buffer,
  msg: Buffer,
  sig: Buffer
): Promise<boolean> {
  let result;
  if (isBrowser()) {
    const expectedSig = await browserHmacSha512Sign(key, msg);
    result = equalConstTime(expectedSig, sig);
  } else if (isNode()) {
    const expectedSig = nodeHmacSha512Sign(key, msg);
    result = equalConstTime(expectedSig, sig);
  } else {
    const expectedSig = fallbackHmacSha512Sign(key, msg);
    result = equalConstTime(expectedSig, sig);
  }
  return result;
}
