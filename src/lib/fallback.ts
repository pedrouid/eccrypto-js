import aesJs from 'aes-js';
import randomBytes from 'randombytes';
import * as hash from 'hash.js';

import * as pkcs7 from './pkcs7';

import { arrayToBuffer, hexToBuffer } from '../helpers/util';
import { SHA256_NODE_ALGO, HEX_ENC } from '../helpers/constants';

export function fallbackRandomBytes(length: number): Buffer {
  return randomBytes(length);
}

export async function fallbackAesEncrypt(
  iv: Buffer,
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  const aesCbc = new aesJs.ModeOfOperation.cbc(key, iv);
  const padded = arrayToBuffer(pkcs7.pad(data));
  const encryptedBytes = aesCbc.encrypt(padded);
  return Buffer.from(encryptedBytes);
}

export async function fallbackAesDecrypt(
  iv: Buffer,
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  const aesCbc = new aesJs.ModeOfOperation.cbc(key, iv);
  const encryptedBytes = aesCbc.decrypt(data);
  const padded = Buffer.from(encryptedBytes);
  const result = arrayToBuffer(pkcs7.unpad(padded));
  return result;
}

export async function fallbackCreateHmac(
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  const result = hash
    .hmac((hash as any)[SHA256_NODE_ALGO], key)
    .update(data)
    .digest(HEX_ENC);
  return hexToBuffer(result);
}

export async function fallbackSha256(msg: Buffer): Promise<Buffer> {
  const result = hash
    .sha256()
    .update(msg)
    .digest(HEX_ENC);
  return hexToBuffer(result);
}

export async function fallbackSha512(msg: Buffer): Promise<Buffer> {
  const result = hash
    .sha512()
    .update(msg)
    .digest(HEX_ENC);
  return hexToBuffer(result);
}
