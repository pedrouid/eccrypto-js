import aesJs from 'aes-js';

export function aesCbcEncrypt(
  iv: Buffer,
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  return new Promise(resolve => {
    const aesCbc = new aesJs.ModeOfOperation.cbc(key, iv);
    const encryptedBytes = aesCbc.encrypt(data);
    resolve(Buffer.from(encryptedBytes));
  });
}

export function aesCbcDecrypt(
  iv: Buffer,
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  return new Promise(resolve => {
    const aesCbc = new aesJs.ModeOfOperation.cbc(key, iv);
    const encryptedBytes = aesCbc.decrypt(data);
    resolve(Buffer.from(encryptedBytes));
  });
}
