import {
  getTestMessageToEncrypt,
  testRandomBytes,
  testAesEncrypt,
  testAesDecrypt,
  compare,
} from './common';

describe('AES', () => {
  let keyLength: number;
  let key: Buffer;
  let ivLength: number;
  let iv: Buffer;
  let data: Buffer;

  beforeEach(async () => {
    keyLength = 32;
    key = testRandomBytes(keyLength);
    ivLength = 16;
    iv = testRandomBytes(ivLength);
    const toEncrypt = await getTestMessageToEncrypt();
    data = toEncrypt.msg;
  });

  it('should encrypt sucessfully', async () => {
    const ciphertext = await testAesEncrypt(iv, key, data);
    expect(ciphertext).toBeTruthy();
  });

  it('should decrypt sucessfully', async () => {
    const ciphertext = await testAesEncrypt(iv, key, data);
    const result = await testAesDecrypt(iv, key, ciphertext);
    expect(result).toBeTruthy();
  });

  it('decrypted should match input', async () => {
    const ciphertext = await testAesEncrypt(iv, key, data);
    const result = await testAesDecrypt(iv, key, ciphertext);
    expect(compare(data, result)).toBeTruthy();
  });
});
