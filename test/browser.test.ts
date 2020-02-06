import * as eccryptoJS from '../src';
import { testRandomBytes } from './common';

describe('Browser', () => {
  let length: number;
  let key: Buffer;

  beforeEach(async () => {
    length = 32;
    key = testRandomBytes(length);
  });

  it.skip('should import key from buffer successfully', async () => {
    const result = await eccryptoJS.browserImportKey(key);
    expect(result).toBeTruthy();
  });
});
