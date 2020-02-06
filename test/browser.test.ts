import * as eccryptoJS from '../src';
import { testRandomBytes } from './common';
// import { WebCrypto } from 'node-webcrypto-ossl';

// declare global {
//   interface Window {
//     crypto: SubtleCrypto;
//   }
// }

describe('Browser', () => {
  let length: number;
  let key: Buffer;

  beforeEach(async () => {
    // window.crypto = new WebCrypto();
    length = 32;
    key = testRandomBytes(length);
  });

  it.skip('should import key from buffer successfully', async () => {
    const result = await eccryptoJS.browserImportKey(key);
    expect(result).toBeTruthy();
  });
});
