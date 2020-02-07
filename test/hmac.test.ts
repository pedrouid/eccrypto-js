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
  let mac: Buffer;

  beforeEach(async () => {
    const toEncrypt = await getTestMessageToEncrypt();
    msg = toEncrypt.msg;
    iv = testRandomBytes(16);
    key = testRandomBytes(32);
    macKey = Buffer.concat([iv, key]);
    dataToMac = Buffer.concat([iv, key, msg]);
    mac = await testHmacSign(macKey, dataToMac);
  });

  it('should sign sucessfully', async () => {
    expect(mac).toBeTruthy();
  });

  it('should verify sucessfully', async () => {
    const macGood = await testHmacVerify(macKey, dataToMac, mac);
    expect(macGood).toBeTruthy();
  });
});
