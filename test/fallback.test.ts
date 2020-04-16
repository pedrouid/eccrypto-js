import * as nodeLib from '../src/lib/node';
import * as browserLib from '../src/lib/browser';
import * as fallbackLib from '../src/lib/fallback';
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
  describe('RandomBytes', () => {
    let length: number;
    let key: Buffer;

    beforeEach(async () => {
      length = 32;
      key = nodeLib.nodeRandomBytes(length);
    });

    it('should generate random bytes sucessfully', async () => {
      expect(key).toBeTruthy();
    });

    it('should match request byte length', async () => {
      const isMatch = key.length === length;
      expect(isMatch).toBeTruthy();
    });
  });

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
      const ciphertext = fallbackLib.fallbackAesEncrypt(iv, key, data);
      expect(ciphertext).toBeTruthy();
    });

    it('should decrypt successfully', async () => {
      const ciphertext = fallbackLib.fallbackAesEncrypt(iv, key, data);
      const result = fallbackLib.fallbackAesDecrypt(iv, key, ciphertext);
      expect(result).toBeTruthy();
      expect(compare(data, result)).toBeTruthy();
    });

    it('ciphertext should be decrypted by NodeJS', async () => {
      const ciphertext = fallbackLib.fallbackAesEncrypt(iv, key, data);
      const result = nodeLib.nodeAesDecrypt(iv, key, ciphertext);
      expect(result).toBeTruthy();
      expect(compare(data, result)).toBeTruthy();
    });

    it('should decrypt ciphertext from NodeJS', async () => {
      const ciphertext = nodeLib.nodeAesEncrypt(iv, key, data);
      const result = fallbackLib.fallbackAesDecrypt(iv, key, ciphertext);
      expect(result).toBeTruthy();
      expect(compare(data, result)).toBeTruthy();
    });

    it('ciphertext should be decrypted by Browser', async () => {
      const ciphertext = fallbackLib.fallbackAesEncrypt(iv, key, data);
      const result = await browserLib.browserAesDecrypt(iv, key, ciphertext);
      expect(result).toBeTruthy();
      expect(compare(data, result)).toBeTruthy();
    });

    it('should decrypt ciphertext from Browser', async () => {
      const ciphertext = await browserLib.browserAesEncrypt(iv, key, data);
      const result = fallbackLib.fallbackAesDecrypt(iv, key, ciphertext);
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
        const output = fallbackLib.fallbackSha256(input);
        expect(compare(output, expectedOutput)).toBeTruthy();
      });

      it('should output with expected length', async () => {
        const input = Buffer.from(TEST_MESSAGE_STR);
        const output = fallbackLib.fallbackSha256(input);
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
        const output = fallbackLib.fallbackSha512(input);
        expect(compare(output, expectedOutput)).toBeTruthy();
      });

      it('should output with expected length', async () => {
        const input = Buffer.from(TEST_MESSAGE_STR);
        const output = fallbackLib.fallbackSha512(input);
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
      mac = fallbackLib.fallbackHmacSha256Sign(macKey, dataToMac);
    });

    it('should sign sucessfully', async () => {
      expect(compare(mac, expectedOutput)).toBeTruthy();
    });

    it('should output with expected length', async () => {
      expect(mac.length === expectedLength).toBeTruthy();
    });
  });
});
