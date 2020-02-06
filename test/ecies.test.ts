import * as eccryptoJS from '../src';
import { testGenerateKeyPair, testEncrypt } from './common';

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
});
