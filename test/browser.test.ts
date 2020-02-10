import * as eccryptoJS from '../src';
import { testRandomBytes } from './common';
import { Crypto } from '@peculiar/webcrypto';

declare global {
  interface Window {
    msCrypto: Crypto;
  }
}

//  using msCrypto because Typescript was complaing read-only
window.msCrypto = new Crypto();

describe('Browser', () => {
  let length: number;
  let key: Buffer;

  beforeEach(async () => {
    length = 32;
    key = testRandomBytes(length);
  });

  it('should return true for isBrowser check', () => {
    const result = eccryptoJS.isBrowser();
    expect(result).toBeTruthy();
  });

  it('should import key from buffer successfully', async () => {
    const result = await eccryptoJS.browserImportKey(key);
    expect(result).toBeTruthy();
  });
});
