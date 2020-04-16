import * as eccryptoJS from '../src';
import {
  TEST_MESSAGE_STR,
  TEST_SHA3_HASH,
  TEST_KECCAK256_HASH,
  compare,
} from './common';

describe('SHA3', () => {
  let expectedLength: number;
  let expectedOutput: Buffer;

  beforeEach(async () => {
    expectedLength = 32;
    expectedOutput = Buffer.from(TEST_SHA3_HASH, 'hex');
  });
  it('should hash buffer sucessfully', async () => {
    const input = Buffer.from(TEST_MESSAGE_STR);
    const output = eccryptoJS.sha3(input);
    expect(compare(output, expectedOutput)).toBeTruthy();
  });

  it('should output with expected length', async () => {
    const input = Buffer.from(TEST_MESSAGE_STR);
    const output = eccryptoJS.sha3(input);
    expect(output.length === expectedLength).toBeTruthy();
  });
});

describe('KECCAK256', () => {
  let expectedLength: number;
  let expectedOutput: Buffer;

  beforeEach(async () => {
    expectedLength = 32;
    expectedOutput = Buffer.from(TEST_KECCAK256_HASH, 'hex');
  });

  it('should hash buffer sucessfully', async () => {
    const input = Buffer.from(TEST_MESSAGE_STR);
    const output = eccryptoJS.keccak256(input);
    expect(compare(output, expectedOutput)).toBeTruthy();
  });

  it('should output with expected length', async () => {
    const input = Buffer.from(TEST_MESSAGE_STR);
    const output = eccryptoJS.keccak256(input);
    expect(output.length === expectedLength).toBeTruthy();
  });
});
