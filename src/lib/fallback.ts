import { computeHmac, SupportedAlgorithm } from '@ethersproject/sha2';
import aesJs from 'aes-js';
// @ts-ignore
import pkcs7 from 'pkcs7';

export async function fallbackCreateHmac(
  key: Buffer,
  msg: Buffer
): Promise<Buffer> {
  const result = computeHmac(SupportedAlgorithm.sha256, key, msg);
  return Buffer.from(result);
}

export async function fallbackAesEncrypt(
  iv: Buffer,
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  const aesCbc = new aesJs.ModeOfOperation.cbc(key, iv);
  const encryptedBytes = aesCbc.encrypt(pkcs7.pad(data));
  return Buffer.from(encryptedBytes);
}

export async function fallbackAesDecrypt(
  iv: Buffer,
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  const aesCbc = new aesJs.ModeOfOperation.cbc(key, iv);
  const encryptedBytes = aesCbc.decrypt(data);
  const result: Buffer = pkcs7.unpad(Buffer.from(encryptedBytes));
  return result;
}
