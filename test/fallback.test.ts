import * as eccryptoJS from '../src';
import { testRandomBytes, getTestMessageToEncrypt, compare } from './common';

describe('Fallback', () => {
  let key: Buffer;
  let iv: Buffer;
  let data: Buffer;

  beforeEach(async () => {
    key = testRandomBytes(32);
    iv = testRandomBytes(16);
    const toEncrypt = await getTestMessageToEncrypt();
    data = toEncrypt.msg;
  });

  it('should encrypt successfully', async () => {
    const ciphertext = await eccryptoJS.fallbackAesEncrypt(iv, key, data);
    expect(ciphertext).toBeTruthy();
  });

  it('should decrypt successfully', async () => {
    const ciphertext = await eccryptoJS.fallbackAesEncrypt(iv, key, data);
    const result = await eccryptoJS.fallbackAesDecrypt(iv, key, ciphertext);
    expect(result).toBeTruthy();
    expect(compare(data, result)).toBeTruthy();
  });

  it('ciphertext should be decrypted by NodeJS', async () => {
    const ciphertext = await eccryptoJS.fallbackAesEncrypt(iv, key, data);
    const result = await eccryptoJS.nodeAesDecrypt(iv, key, ciphertext);
    expect(result).toBeTruthy();
    expect(compare(data, result)).toBeTruthy();
  });

  it('should decrypt ciphertext from NodeJS', async () => {
    const ciphertext = await eccryptoJS.nodeAesEncrypt(iv, key, data);
    const result = await eccryptoJS.fallbackAesDecrypt(iv, key, ciphertext);
    expect(result).toBeTruthy();
    expect(compare(data, result)).toBeTruthy();
  });
});
