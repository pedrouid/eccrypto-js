import { browserSha256, isBrowser, browserSha512 } from './lib/browser';
import { nodeSha256, isNode, nodeSha512 } from './lib/node';
import { fallbackSha256, fallbackSha512 } from './lib/fallback';
import { EMPTY_BUFFER } from './helpers/constants';
import { prepareHash } from './helpers/util';

export async function sha256(msg: Buffer | string): Promise<Buffer> {
  const buf = prepareHash(msg);
  let result = EMPTY_BUFFER;
  if (isBrowser()) {
    result = await browserSha256(buf);
  } else if (isNode()) {
    result = await nodeSha256(buf);
  } else {
    result = await fallbackSha256(buf);
  }
  return result;
}

export async function sha512(msg: Buffer | string): Promise<Buffer> {
  const buf = prepareHash(msg);
  let result = EMPTY_BUFFER;
  if (isBrowser()) {
    result = await browserSha512(buf);
  } else if (isNode()) {
    result = await nodeSha512(buf);
  } else {
    result = await fallbackSha512(buf);
  }
  return result;
}
