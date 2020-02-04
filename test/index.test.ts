import * as eccryptoJS from '../src';
import {
  testGenerateKeyPair,
  testSign,
  testSharedKeys,
  testEncrypt,
} from './common';

describe('ECDSA', () => {
  let keyPair: eccryptoJS.KeyPair;

  beforeEach(() => {
    keyPair = testGenerateKeyPair();
  });

  it('should generate KeyPair', () => {
    expect(keyPair).toBeTruthy();
  });

  it('should sign successfully', async () => {
    const { sig } = await testSign(keyPair.privateKey);
    expect(sig).toBeTruthy();
  });

  it('should verify signature', async () => {
    const { sig, msg } = await testSign(keyPair.privateKey);
    await eccryptoJS.verify(keyPair.publicKey, msg, sig);
    expect(sig).toBeTruthy();
  });
});

describe('ECDH', () => {
  let sharedKey1: Buffer;
  let sharedKey2: Buffer;

  beforeEach(async () => {
    const sharedKeys = await testSharedKeys();
    sharedKey1 = sharedKeys.sharedKey1;
    sharedKey2 = sharedKeys.sharedKey2;
  });

  it('should derive shared keys succesfully', () => {
    expect(sharedKey1).toBeTruthy();
    expect(sharedKey2).toBeTruthy();
  });

  it('derived shared keys should match', () => {
    const isMatch = sharedKey1.toString('hex') === sharedKey2.toString('hex');
    expect(isMatch).toBeTruthy();
  });
});

describe('ECIES', () => {
  let keyPair: eccryptoJS.KeyPair;

  beforeEach(() => {
    keyPair = testGenerateKeyPair();
  });

  it.skip('should encrypt successfully', async () => {
    const encrypted = await testEncrypt(keyPair.publicKey);
    expect(encrypted).toBeTruthy();
  });
});
