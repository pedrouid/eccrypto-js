import { generateKeyPair } from '../src';

describe('ECDSA', () => {
  it('should generate KeyPair', () => {
    const keyPair = generateKeyPair();
    expect(keyPair.privateKey).toBeTruthy();
    expect(keyPair.publicKey).toBeTruthy();
  });
});
