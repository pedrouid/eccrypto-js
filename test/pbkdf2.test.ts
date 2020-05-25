import * as eccryptoJS from '../src';

describe('PBKDF2', () => {
  const password = eccryptoJS.utf8ToBuffer('password');
  const expectedLength = 32;
  let key: Buffer;

  beforeEach(async () => {
    key = await eccryptoJS.pbkdf2(password);
  });

  it('should generate key from password', async () => {
    expect(key).toBeTruthy();
  });

  it('should generate key with 32 byte length', async () => {
    expect(key.length === expectedLength).toBeTruthy();
  });
});
