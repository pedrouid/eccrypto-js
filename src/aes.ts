import aesJs from 'aes-js';

export async function aesCbcEncrypt(
  iv: Buffer,
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  const aesCbc = new aesJs.ModeOfOperation.cbc(key, iv);
  const encryptedBytes = aesCbc.encrypt(data);
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
