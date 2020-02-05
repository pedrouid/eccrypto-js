import { SIGN_OP, VERIFY_OP, EMPTY_BUFFER } from './constants';

import { equalConstTime } from './validators';
import { isBrowser, browserCreateHmac } from './browser';
import { fallbackCreateHmac } from './fallback';
import { isNode, nodeCreateHmac } from './node';

export function getHmac(op: string) {
  return async (key: Buffer, msg: Buffer, sig?: Buffer) => {
    if (isBrowser()) {
      if (op === SIGN_OP) {
        const result = await browserCreateHmac(msg, key);
        return result;
      } else if (op === VERIFY_OP && sig) {
        const expectedSig = await browserCreateHmac(msg, key);
        const result = equalConstTime(expectedSig, sig);
        return result;
      }
    } else if (isNode()) {
      if (op === SIGN_OP) {
        const result = await nodeCreateHmac(key, msg);
        return result;
      } else if (op === VERIFY_OP && sig) {
        const expectedSig = await nodeCreateHmac(key, msg);
        const result = equalConstTime(expectedSig, sig);
        return result;
      }
    } else {
      if (op === SIGN_OP) {
        const result = await fallbackCreateHmac(key, msg);
        return result;
      } else if (op === VERIFY_OP && sig) {
        const expectedSig = await fallbackCreateHmac(key, msg);
        const result = equalConstTime(expectedSig, sig);
        return result;
      }
    }
    return op === SIGN_OP ? EMPTY_BUFFER : false;
  };
}
