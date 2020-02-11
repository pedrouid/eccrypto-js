import * as eccryptoJS from '../src';
import {
  TEST_MESSAGE_STR,
  compare,
  TEST_SHA256_HASH,
  TEST_SHA512_HASH,
} from './common';

describe('SHA256', () => {
  let expectedLength: number;
  let expectedOutput: Buffer;

  beforeEach(async () => {
    expectedLength = 32;
    expectedOutput = Buffer.from(TEST_SHA256_HASH, 'hex');
  });

  it('should hash buffer sucessfully', async () => {
    const input = Buffer.from(TEST_MESSAGE_STR);
    const output = await eccryptoJS.sha256(input);
    expect(compare(output, expectedOutput)).toBeTruthy();
  });

  it('should output with expected length', async () => {
    const input = Buffer.from(TEST_MESSAGE_STR);
    const output = await eccryptoJS.sha256(input);
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
    const output = await eccryptoJS.sha512(input);
    expect(compare(output, expectedOutput)).toBeTruthy();
  });

  it('should output with expected length', async () => {
    const input = Buffer.from(TEST_MESSAGE_STR);
    const output = await eccryptoJS.sha512(input);
    expect(output.length === expectedLength).toBeTruthy();
  });
});
