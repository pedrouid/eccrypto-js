import * as eccryptoJS from '../src';
import { TEST_MESSAGE, compare } from './common';

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
    const output = await eccryptoJS.sha256(input);
    expect(compare(output, expectedOutput)).toBeTruthy();
  });

  it('should hash hex string sucessfully', async () => {
    const input = Buffer.from(TEST_MESSAGE).toString();
    const output = await eccryptoJS.sha256(input);
    expect(compare(output, expectedOutput)).toBeTruthy();
  });

  it('should hash utf8 string sucessfully', async () => {
    const input = TEST_MESSAGE;
    const output = await eccryptoJS.sha256(input);
    expect(compare(output, expectedOutput)).toBeTruthy();
  });

  it('should output with expected length', async () => {
    const input = Buffer.from(TEST_MESSAGE);
    const output = await eccryptoJS.sha256(input);
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
    const output = await eccryptoJS.sha512(input);
    expect(compare(output, expectedOutput)).toBeTruthy();
  });

  it('should hash hex string sucessfully', async () => {
    const input = Buffer.from(TEST_MESSAGE).toString();
    const output = await eccryptoJS.sha512(input);
    expect(compare(output, expectedOutput)).toBeTruthy();
  });

  it('should hash utf8 string sucessfully', async () => {
    const input = TEST_MESSAGE;
    const output = await eccryptoJS.sha512(input);
    expect(compare(output, expectedOutput)).toBeTruthy();
  });

  it('should output with expected length', async () => {
    const input = Buffer.from(TEST_MESSAGE);
    const output = await eccryptoJS.sha512(input);
    expect(output.length === expectedLength).toBeTruthy();
  });
});
