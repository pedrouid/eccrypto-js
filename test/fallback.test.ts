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

  it('should encrypted successfully', async () => {
    const encrypted = await eccryptoJS.fallbackAesEncrypt(iv, key, data);
    expect(encrypted).toBeTruthy();
  });

  it('should decrypt successfully', async () => {
    const encrypted = await eccryptoJS.fallbackAesEncrypt(iv, key, data);
    const decrypted = await eccryptoJS.fallbackAesDecrypt(iv, key, encrypted);
    expect(decrypted).toBeTruthy();
    expect(compare(data, decrypted)).toBeTruthy();
  });

  it('payload should be decrypted by NodeJS', async () => {
    const encrypted = await eccryptoJS.fallbackAesEncrypt(iv, key, data);
    const decrypted = await eccryptoJS.nodeAesDecrypt(iv, key, encrypted);
    expect(decrypted).toBeTruthy();
    expect(compare(data, decrypted)).toBeTruthy();
  });

  it('should decrypt payload from NodeJS', async () => {
    const encrypted = await eccryptoJS.nodeAesEncrypt(iv, key, data);
    const decrypted = await eccryptoJS.fallbackAesDecrypt(iv, key, encrypted);
    expect(decrypted).toBeTruthy();
    expect(compare(data, decrypted)).toBeTruthy();
  });
});
