import * as eccryptoJS from '../src';
import {
  testRandomBytes,
  getTestMessageToEncrypt,
  compare,
  TEST_MESSAGE_STR,
  TEST_SHA256_HASH,
  TEST_SHA512_HASH,
  TEST_PRIVATE_KEY,
  TEST_FIXED_IV,
  TEST_HMAC_SIG,
} from './common';
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

  describe('SHA2', () => {
    describe('SHA256', () => {
      let expectedLength: number;
      let expectedOutput: Buffer;

      beforeEach(async () => {
        expectedLength = 32;
        expectedOutput = Buffer.from(TEST_SHA256_HASH, 'hex');
      });
      it('should hash buffer sucessfully', async () => {
        const input = Buffer.from(TEST_MESSAGE_STR);
        const output = await eccryptoJS.fallbackSha256(input);
        expect(compare(output, expectedOutput)).toBeTruthy();
      });

      it('should output with expected length', async () => {
        const input = Buffer.from(TEST_MESSAGE_STR);
        const output = await eccryptoJS.fallbackSha256(input);
        expect(output.length === expectedLength).toBeTruthy();
      });
    });

    describe('SHA512', () => {
      let expectedLength: number;
      let expectedOutput: Buffer;

      beforeEach(async () => {
        expectedLength = 64;
        expectedOutput = Buffer.from(TEST_SHA512_HASH, 'hex');
      });

      it('should hash buffer sucessfully', async () => {
        const input = Buffer.from(TEST_MESSAGE_STR);
        const output = await eccryptoJS.fallbackSha512(input);
        expect(compare(output, expectedOutput)).toBeTruthy();
      });

      it('should output with expected length', async () => {
        const input = Buffer.from(TEST_MESSAGE_STR);
        const output = await eccryptoJS.fallbackSha512(input);
        expect(output.length === expectedLength).toBeTruthy();
      });
    });
  });

  describe('HMAC', () => {
    const msg = Buffer.from(TEST_MESSAGE_STR);
    const iv = Buffer.from(TEST_FIXED_IV, 'hex');
    const key = Buffer.from(TEST_PRIVATE_KEY, 'hex');
    const macKey = Buffer.concat([iv, key]);
    const dataToMac = Buffer.concat([iv, key, msg]);
    const expectedLength = 32;
    const expectedOutput = Buffer.from(TEST_HMAC_SIG, 'hex');

    let mac: Buffer;

    beforeEach(async () => {
      mac = await eccryptoJS.fallbackCreateHmac(macKey, dataToMac);
    });

    it('should sign sucessfully', async () => {
      expect(compare(mac, expectedOutput)).toBeTruthy();
    });

    it('should output with expected length', async () => {
      expect(mac.length === expectedLength).toBeTruthy();
    });
  });
});
