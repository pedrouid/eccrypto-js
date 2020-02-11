import * as eccryptoJS from '../src';
import { testGenerateKeyPair, testEncrypt, compare } from './common';

describe('ECIES', () => {
  let keyPair: eccryptoJS.KeyPair;

  beforeEach(() => {
    keyPair = testGenerateKeyPair();
  });

  it('should encrypt successfully', async () => {
    const { encrypted } = await testEncrypt(keyPair.publicKey);
    expect(encrypted).toBeTruthy();
  });

  it('should decrypt successfully', async () => {
    const { encrypted } = await testEncrypt(keyPair.publicKey);

    const decrypted = await eccryptoJS.decrypt(keyPair.privateKey, encrypted);
    expect(decrypted).toBeTruthy();
  });

  it('decrypted result should match input', async () => {
    const { str, encrypted } = await testEncrypt(keyPair.publicKey);

    const decrypted = await eccryptoJS.decrypt(keyPair.privateKey, encrypted);
    expect(decrypted).toBeTruthy();

    const isMatch = decrypted.toString() === str;
    expect(isMatch).toBeTruthy();
  });

  it('should serialize successfully', async () => {
    const { encrypted } = await testEncrypt(keyPair.publicKey);
    const expectedLength =
      encrypted.ciphertext.length +
      eccryptoJS.compress(encrypted.ephemPublicKey).length +
      encrypted.iv.length +
      encrypted.mac.length;
    const serialized = eccryptoJS.serialize(encrypted);
    expect(serialized).toBeTruthy();
    expect(serialized.length === expectedLength).toBeTruthy();
  });

  it('should deserialize successfully', async () => {
    const { encrypted } = await testEncrypt(keyPair.publicKey);
    const serialized = eccryptoJS.serialize(encrypted);
    const deserialized = eccryptoJS.deserialize(serialized);
    expect(deserialized).toBeTruthy();
    expect(compare(deserialized.ciphertext, encrypted.ciphertext)).toBeTruthy();
    expect(
      compare(deserialized.ephemPublicKey, encrypted.ephemPublicKey)
    ).toBeTruthy();
    expect(compare(deserialized.iv, encrypted.iv)).toBeTruthy();
    expect(compare(deserialized.mac, encrypted.mac)).toBeTruthy();
  });
});
