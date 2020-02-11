import { browserSha256, isBrowser, browserSha512 } from './lib/browser';
import { nodeSha256, isNode, nodeSha512 } from './lib/node';
import { fallbackSha256, fallbackSha512 } from './lib/fallback';
import { EMPTY_BUFFER } from './helpers/constants';

export async function sha256(msg: Buffer): Promise<Buffer> {
  let result = EMPTY_BUFFER;
  if (isBrowser()) {
    result = await browserSha256(msg);
  } else if (isNode()) {
    result = await nodeSha256(msg);
  } else {
    result = await fallbackSha256(msg);
  }
  return result;
}

export async function sha512(msg: Buffer): Promise<Buffer> {
  let result = EMPTY_BUFFER;
  if (isBrowser()) {
    result = await browserSha512(msg);
  } else if (isNode()) {
    result = await nodeSha512(msg);
  } else {
    result = await fallbackSha512(msg);
  }
  return result;
}
