import {
  getTestMessageToEncrypt,
  testRandomBytes,
  testAesEncrypt,
  testAesDecrypt,
  compare,
} from './common';

describe('AES', () => {
  let msg: Buffer;
  let iv: Buffer;
  let key: Buffer;

  beforeEach(async () => {
    const toEncrypt = await getTestMessageToEncrypt();
    msg = toEncrypt.msg;
    iv = testRandomBytes(16);
    key = testRandomBytes(32);
  });

  it('should encrypt sucessfully', async () => {
    const ciphertext = await testAesEncrypt(iv, key, msg);
    expect(ciphertext).toBeTruthy();
  });

  it('should decrypt sucessfully', async () => {
    const ciphertext = await testAesEncrypt(iv, key, msg);
    const result = await testAesDecrypt(iv, key, ciphertext);
    expect(result).toBeTruthy();
  });

  it('decrypted should match input', async () => {
    const ciphertext = await testAesEncrypt(iv, key, msg);
    const result = await testAesDecrypt(iv, key, ciphertext);
    expect(compare(msg, result)).toBeTruthy();
  });
});
