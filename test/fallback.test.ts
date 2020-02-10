import * as eccryptoJS from '../src';
import { testRandomBytes, getTestMessageToEncrypt, compare } from './common';
import { Crypto } from '@peculiar/webcrypto';

declare global {
  interface Window {
    msCrypto: Crypto;
  }
}

//  using msCrypto because Typescript was complaing read-only
window.msCrypto = new Crypto();

describe('Fallback', () => {
  describe('AES', () => {
    let keyLength: number;
    let key: Buffer;
    let ivLength: number;
    let iv: Buffer;
    let data: Buffer;

    beforeEach(async () => {
      keyLength = 32;
      key = testRandomBytes(keyLength);
      ivLength = 16;
      iv = testRandomBytes(ivLength);
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

    it('ciphertext should be decrypted by Browser', async () => {
      const ciphertext = await eccryptoJS.fallbackAesEncrypt(iv, key, data);
      const result = await eccryptoJS.browserAesDecrypt(iv, key, ciphertext);
      expect(result).toBeTruthy();
      expect(compare(data, result)).toBeTruthy();
    });

    it('should decrypt ciphertext from Browser', async () => {
      const ciphertext = await eccryptoJS.browserAesEncrypt(iv, key, data);
      const result = await eccryptoJS.fallbackAesDecrypt(iv, key, ciphertext);
      expect(result).toBeTruthy();
      expect(compare(data, result)).toBeTruthy();
    });
  });
});
