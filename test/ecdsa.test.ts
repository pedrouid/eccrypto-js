import * as eccryptoJS from '../src';
import { testGenerateKeyPair, testSign } from './common';

describe('ECDSA', () => {
  let keyPair: eccryptoJS.KeyPair;

  beforeEach(() => {
    keyPair = testGenerateKeyPair();
  });

  it('should generate KeyPair', () => {
    expect(keyPair).toBeTruthy();
  });

  it('should sign successfully with DER signatures', async () => {
    const { sig } = await testSign(keyPair.privateKey);
    expect(sig).toBeTruthy();
  });

  it('should verify DER signatures successfully', async () => {
    const { sig, msg } = await testSign(keyPair.privateKey);
    await eccryptoJS.verify(keyPair.publicKey, msg, sig);
  });

  it('should sign successfully with non-DER signatures', async () => {
    const { sig } = await testSign(keyPair.privateKey, true);
    expect(sig).toBeTruthy();
  });

  it('should verify non-DER signatures successfully', async () => {
    const { sig, msg } = await testSign(keyPair.privateKey, true);
    await eccryptoJS.verify(keyPair.publicKey, msg, sig);
  });
});
