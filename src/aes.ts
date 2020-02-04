import aesJs from 'aes-js';
// @ts-ignore
import pkcs7 from 'pkcs7';

export async function aesCbcEncrypt(
  iv: Buffer,
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  const aesCbc = new aesJs.ModeOfOperation.cbc(key, iv);
  const encryptedBytes = aesCbc.encrypt(pkcs7.pad(data));
  return Buffer.from(encryptedBytes);
}

export async function aesCbcDecrypt(
  iv: Buffer,
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  const aesCbc = new aesJs.ModeOfOperation.cbc(key, iv);
  const encryptedBytes = aesCbc.decrypt(data);
  return Buffer.from(encryptedBytes);
}
