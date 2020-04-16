import * as eccryptoJS from '../src';
import * as ellipticLib from '../src/lib/elliptic';
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
    eccryptoJS.verify(keyPair.publicKey, msg, sig);
  });

  it('should throw when recovering from DER signatures', async () => {
    const { sig, msg } = await testSign(keyPair.privateKey);
    expect(() => ellipticLib.ellipticRecover(sig, msg)).toThrow(
      'Cannot recover from DER signatures'
    );
  });

  it('should sign successfully with RSV signatures', async () => {
    const { sig } = await testSign(keyPair.privateKey, true);
    expect(sig).toBeTruthy();
  });

  it('should verify RSV signatures successfully', async () => {
    const { sig, msg } = await testSign(keyPair.privateKey, true);
    eccryptoJS.verify(keyPair.publicKey, msg, sig);
  });

  it('should recover RSV signatures successfully', async () => {
    const { sig, msg } = await testSign(keyPair.privateKey, true);
    const recovered = ellipticLib.ellipticRecover(sig, msg);
    expect(compare(keyPair.publicKey, recovered)).toBeTruthy();
  });
});
