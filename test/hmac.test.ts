import {
  testHmacSign,
  testHmacVerify,
  TEST_MESSAGE_STR,
  compare,
  TEST_FIXED_KEY,
  TEST_FIXED_IV,
  TEST_HMAC_SIG,
} from './common';

describe('HMAC', () => {
  const msg: Buffer = Buffer.from(TEST_MESSAGE_STR);
  const iv: Buffer = Buffer.from(TEST_FIXED_IV, 'hex');
  const key: Buffer = Buffer.from(TEST_FIXED_KEY, 'hex');
  const macKey: Buffer = Buffer.concat([iv, key]);
  const dataToMac: Buffer = Buffer.concat([iv, key, msg]);
  const expectedLength: number = 32;
  const expectedOutput: Buffer = Buffer.from(TEST_HMAC_SIG, 'hex');

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
