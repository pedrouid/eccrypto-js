import * as eccryptoJS from '../src';
import { testGenerateKeyPair, testSign, compare } from './common';

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

  it('should throw when recovering from DER signatures', async () => {
    const { sig, msg } = await testSign(keyPair.privateKey);
    expect(() => eccryptoJS.ellipticRecover(sig, msg)).toThrow(
      'Cannot recover from DER signatures'
    );
  });

  it('should sign successfully with RSV signatures', async () => {
    const { sig } = await testSign(keyPair.privateKey, true);
    expect(sig).toBeTruthy();
  });

  it('should verify RSV signatures successfully', async () => {
    const { sig, msg } = await testSign(keyPair.privateKey, true);
    await eccryptoJS.verify(keyPair.publicKey, msg, sig);
  });

  it('should recover RSV signatures successfully', async () => {
    const { sig, msg } = await testSign(keyPair.privateKey, true);
    const recovered = eccryptoJS.ellipticRecover(sig, msg);
    expect(compare(keyPair.publicKey, recovered)).toBeTruthy();
  });
});
