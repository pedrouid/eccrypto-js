import {
  getTestMessageToEncrypt,
  testRandomBytes,
  testHmacSign,
  testHmacVerify,
} from './common';

describe('HMAC', () => {
  let msg: Buffer;
  let iv: Buffer;
  let key: Buffer;
  let macKey: Buffer;
  let dataToMac: Buffer;

  beforeEach(async () => {
    const toEncrypt = await getTestMessageToEncrypt();
    msg = toEncrypt.msg;
    iv = testRandomBytes(16);
    key = testRandomBytes(32);
    macKey = Buffer.concat([iv, key]);
    dataToMac = Buffer.concat([iv, key, msg]);
  });

  it('should sign sucessfully', async () => {
    const mac = await testHmacSign(macKey, dataToMac);
    expect(mac).toBeTruthy();
  });

  // TODO: fix hmac verify test
  it.skip('should verify sucessfully', async () => {
    const mac = await testHmacSign(macKey, dataToMac);
    const result = await testHmacVerify(key, dataToMac, mac);
    expect(result).toBeTruthy();
  });
});
