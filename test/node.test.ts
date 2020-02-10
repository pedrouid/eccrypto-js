import * as eccryptoJS from '../src';
import {
  testRandomBytes,
  getTestMessageToEncrypt,
  compare,
  TEST_MESSAGE,
} from './common';
import { Crypto } from '@peculiar/webcrypto';

declare global {
  interface Window {
    msCrypto: Crypto;
  }
}

//  using msCrypto because Typescript was complaing read-only
window.msCrypto = new Crypto();

describe('NodeJS', () => {
  describe('isNode', () => {
    it('should return true', () => {
      const result = eccryptoJS.isNode();
      expect(result).toBeTruthy();
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
      const ciphertext = await eccryptoJS.nodeAesEncrypt(iv, key, data);
      expect(ciphertext).toBeTruthy();
    });

    it('should decrypt successfully', async () => {
      const ciphertext = await eccryptoJS.nodeAesEncrypt(iv, key, data);
      const result = await eccryptoJS.nodeAesDecrypt(iv, key, ciphertext);
      expect(result).toBeTruthy();
      expect(compare(data, result)).toBeTruthy();
    });

    it('ciphertext should be decrypted by Fallback', async () => {
      const ciphertext = await eccryptoJS.nodeAesEncrypt(iv, key, data);
      const result = await eccryptoJS.fallbackAesDecrypt(iv, key, ciphertext);
      expect(result).toBeTruthy();
      expect(compare(data, result)).toBeTruthy();
    });

    it('should decrypt ciphertext from Fallback', async () => {
      const ciphertext = await eccryptoJS.fallbackAesEncrypt(iv, key, data);
      const result = await eccryptoJS.nodeAesDecrypt(iv, key, ciphertext);
      expect(result).toBeTruthy();
      expect(compare(data, result)).toBeTruthy();
    });

    it('ciphertext should be decrypted by Browser', async () => {
      const ciphertext = await eccryptoJS.nodeAesEncrypt(iv, key, data);
      const result = await eccryptoJS.browserAesDecrypt(iv, key, ciphertext);
      expect(result).toBeTruthy();
      expect(compare(data, result)).toBeTruthy();
    });

    it('should decrypt ciphertext from Browser', async () => {
      const ciphertext = await eccryptoJS.browserAesEncrypt(iv, key, data);
      const result = await eccryptoJS.nodeAesDecrypt(iv, key, ciphertext);
      expect(result).toBeTruthy();
      expect(compare(data, result)).toBeTruthy();
    });
  });

  describe('SHA2', () => {
    const SHA256_HASH =
      '3819ff1b5125e14102ae429929e815d6fada758d4a6886a03b1b1c64aca3a53a';

    const SHA512_HASH =
      '1ea15b17a445109c6709d54e8d3e3640ad2d8b87a8b020a2d99e2123d24a42eda8b6d3d71419438a7fe8ac3d8b7f1968113544b7ef4289340a5810f05cb2479f';

    describe('SHA256', () => {
      let expectedLength: number;
      let expectedOutput: Buffer;

      beforeEach(async () => {
        expectedLength = 32;
        expectedOutput = Buffer.from(SHA256_HASH, 'hex');
      });
      it('should hash buffer sucessfully', async () => {
        const input = Buffer.from(TEST_MESSAGE);
        const output = await eccryptoJS.nodeSha256(input);
        expect(compare(output, expectedOutput)).toBeTruthy();
      });

      it('should output with expected length', async () => {
        const input = Buffer.from(TEST_MESSAGE);
        const output = await eccryptoJS.nodeSha256(input);
        expect(output.length === expectedLength).toBeTruthy();
      });
    });

    describe('SHA512', () => {
      let expectedLength: number;
      let expectedOutput: Buffer;

      beforeEach(async () => {
        expectedLength = 64;
        expectedOutput = Buffer.from(SHA512_HASH, 'hex');
      });

      it('should hash buffer sucessfully', async () => {
        const input = Buffer.from(TEST_MESSAGE);
        const output = await eccryptoJS.nodeSha512(input);
        expect(compare(output, expectedOutput)).toBeTruthy();
      });

      it('should output with expected length', async () => {
        const input = Buffer.from(TEST_MESSAGE);
        const output = await eccryptoJS.nodeSha512(input);
        expect(output.length === expectedLength).toBeTruthy();
      });
    });
  });
});
