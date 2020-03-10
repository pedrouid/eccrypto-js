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
    console.log('ecdsa', 'DER', sig.toString('hex'));
    expect(sig).toBeTruthy();
  });

  it('should verify DER signatures successfully', async () => {
    const { sig, msg } = await testSign(keyPair.privateKey);
    await eccryptoJS.verify(keyPair.publicKey, msg, sig);
  });

  it('should sign successfully with non-DER signatures', async () => {
    const { sig } = await testSign(keyPair.privateKey, true);
    console.log('ecdsa', 'RSV', sig.toString('hex'));
    expect(sig).toBeTruthy();
  });

  it('should verify non-DER signatures successfully', async () => {
    const { sig, msg } = await testSign(keyPair.privateKey, true);
    await eccryptoJS.verify(keyPair.publicKey, msg, sig);
  });
});
