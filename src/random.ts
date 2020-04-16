import { isValidKeyLength } from './helpers';
import { isBrowser, browserRandomBytes } from './lib/browser';
import { isNode, nodeRandomBytes } from './lib/node';
import { fallbackRandomBytes } from './lib/fallback';

export function randomBytes(length: number): Buffer {
  if (!isValidKeyLength(length)) {
    throw new Error(`randomBytes - invalid key length: ${length}`);
  }
  let result;
  if (isBrowser()) {
    result = browserRandomBytes(length);
  } else if (isNode()) {
    result = nodeRandomBytes(length);
  } else {
    result = fallbackRandomBytes(length);
  }
  return result;
}
