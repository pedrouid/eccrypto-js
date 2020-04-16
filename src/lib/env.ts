import { getBrowerCrypto, getSubtleCrypto } from './browser';

export function isBrowser(): boolean {
  return !!getBrowerCrypto() && !!getSubtleCrypto();
}

export function isNode(): boolean {
  let result = false;
  try {
    const crypto = require('crypto');
    if (crypto) {
      result = true;
    }
  } catch (e) {
    // do nothing
  }
  return result;
}
