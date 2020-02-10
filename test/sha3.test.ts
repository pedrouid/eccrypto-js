import * as eccryptoJS from '../src';
import { TEST_MESSAGE_STR, compare } from './common';

const SHA3_HASH =
  '66c68da92b01108b0e37a2cc80877b0358f27f03de9a8ce95bc499ff70dd4c63';

const KECCAK256_HASH =
  '2339863461be3f2dbbc5f995c5bf6953ee73f6437f37b0b44de4e67088bcd4c2';

describe('SHA3', () => {
  let expectedLength: number;
  let expectedOutput: Buffer;

  beforeEach(async () => {
    expectedLength = 32;
    expectedOutput = Buffer.from(SHA3_HASH, 'hex');
  });
  it('should hash buffer sucessfully', async () => {
    const input = Buffer.from(TEST_MESSAGE_STR);
    const output = await eccryptoJS.sha3(input);
    expect(compare(output, expectedOutput)).toBeTruthy();
  });

  it('should hash hex string sucessfully', async () => {
    const input = Buffer.from(TEST_MESSAGE_STR).toString();
    const output = await eccryptoJS.sha3(input);
    expect(compare(output, expectedOutput)).toBeTruthy();
  });

  it('should hash utf8 string sucessfully', async () => {
    const input = TEST_MESSAGE_STR;
    const output = await eccryptoJS.sha3(input);
    expect(compare(output, expectedOutput)).toBeTruthy();
  });

  it('should output with expected length', async () => {
    const input = Buffer.from(TEST_MESSAGE_STR);
    const output = await eccryptoJS.sha3(input);
    expect(output.length === expectedLength).toBeTruthy();
  });
});

describe('KECCAK256', () => {
  let expectedLength: number;
  let expectedOutput: Buffer;

  beforeEach(async () => {
    expectedLength = 32;
    expectedOutput = Buffer.from(KECCAK256_HASH, 'hex');
  });

  it('should hash buffer sucessfully', async () => {
    const input = Buffer.from(TEST_MESSAGE_STR);
    const output = await eccryptoJS.keccak256(input);
    expect(compare(output, expectedOutput)).toBeTruthy();
  });

  it('should hash hex string sucessfully', async () => {
    const input = Buffer.from(TEST_MESSAGE_STR).toString();
    const output = await eccryptoJS.keccak256(input);
    expect(compare(output, expectedOutput)).toBeTruthy();
  });

  it('should hash utf8 string sucessfully', async () => {
    const input = TEST_MESSAGE_STR;
    const output = await eccryptoJS.keccak256(input);
    expect(compare(output, expectedOutput)).toBeTruthy();
  });

  it('should output with expected length', async () => {
    const input = Buffer.from(TEST_MESSAGE_STR);
    const output = await eccryptoJS.keccak256(input);
    expect(output.length === expectedLength).toBeTruthy();
  });
});
