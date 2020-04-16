import { browserSha256, isBrowser, browserSha512 } from './lib/browser';
import { nodeSha256, isNode, nodeSha512, nodeRipemd160 } from './lib/node';
import {
  fallbackSha256,
  fallbackSha512,
  fallbackRipemd160,
} from './lib/fallback';
import { EMPTY_BUFFER } from './helpers';

export async function sha256(msg: Buffer): Promise<Buffer> {
  let result = EMPTY_BUFFER;
  if (isBrowser()) {
    result = await browserSha256(msg);
  } else if (isNode()) {
    result = nodeSha256(msg);
  } else {
    result = fallbackSha256(msg);
  }
  return result;
}

export async function sha512(msg: Buffer): Promise<Buffer> {
  let result = EMPTY_BUFFER;
  if (isBrowser()) {
    result = await browserSha512(msg);
  } else if (isNode()) {
    result = nodeSha512(msg);
  } else {
    result = fallbackSha512(msg);
  }
  return result;
}

export async function ripemd160(msg: Buffer): Promise<Buffer> {
  let result = EMPTY_BUFFER;
  if (isNode()) {
    result = nodeRipemd160(msg);
  } else {
    result = fallbackRipemd160(msg);
  }
  return result;
}
