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

  // it('should work', async () => {
  //   const msg =
  //     '0x98098a136202bee5ef5e3fd477ca549e40f5810dee31365923a3ada6e25ff794';
  //   const sig =
  //     '0x73a234f798e877c7cf3aebefc4c200fff728c147e9c5bacffaac451fdea4f5530079992a90274bb8d7690684f4406f28684fa19ac1fff68a97fc356aef8911a81c';
  //   const recovered = ellipticLib.ellipticRecover(
  //     eccryptoJS.hexToBuffer(sig),
  //     eccryptoJS.hexToBuffer(msg)
  //   );
  //   expect(recovered).toEqual(
  //     eccryptoJS.hexToBuffer(
  //       '0x04e76c414d2ff324eb7b05b7b407d03840ee0cc27825eda20e7904fd298e251a44731eb8fbe450bb7ee45fd661f2d57af19ba59e8942e3426b9f8aae096e2e3107'
  //     )
  //   );
  // });
});
