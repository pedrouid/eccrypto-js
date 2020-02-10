import {
  testHmacSign,
  testHmacVerify,
  TEST_MESSAGE_STR,
  compare,
  TEST_PRIVATE_KEY,
  TEST_FIXED_IV,
  TEST_HMAC_SIG,
} from './common';

describe('HMAC', () => {
  const msg = Buffer.from(TEST_MESSAGE_STR);
  const iv = Buffer.from(TEST_FIXED_IV, 'hex');
  const key = Buffer.from(TEST_PRIVATE_KEY, 'hex');
  const macKey = Buffer.concat([iv, key]);
  const dataToMac = Buffer.concat([iv, key, msg]);
  const expectedLength = 32;
  const expectedOutput = Buffer.from(TEST_HMAC_SIG, 'hex');

  let mac: Buffer;

  beforeEach(async () => {
    mac = await testHmacSign(macKey, dataToMac);
  });

  it('should sign sucessfully', async () => {
    expect(compare(mac, expectedOutput)).toBeTruthy();
  });

  it('should output with expected length', async () => {
    expect(mac.length === expectedLength).toBeTruthy();
  });

  it('should verify sucessfully', async () => {
    const macGood = await testHmacVerify(macKey, dataToMac, mac);
    expect(macGood).toBeTruthy();
  });
});
