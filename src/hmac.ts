import { isBrowser, browserCreateHmac } from './lib/browser';
import { fallbackCreateHmac } from './lib/fallback';
import { isNode, nodeCreateHmac } from './lib/node';

import { equalConstTime } from './helpers/validators';
import { SIGN_OP, VERIFY_OP, EMPTY_BUFFER } from './helpers/constants';

export function getHmac(op: string) {
  return async (key: Buffer, msg: Buffer, sig?: Buffer) => {
    if (isBrowser()) {
      if (op === SIGN_OP) {
        const result = await browserCreateHmac(key, msg);
        return result;
      } else if (op === VERIFY_OP && sig) {
        const expectedSig = await browserCreateHmac(key, msg);
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

export const hmacSha256Sign = getHmac(SIGN_OP);
export const hmacSha256Verify = getHmac(VERIFY_OP);
