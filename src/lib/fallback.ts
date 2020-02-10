import aesJs from 'aes-js';
import { arrayify, isHexString } from '@ethersproject/bytes';
import {
  sha256,
  sha512,
  computeHmac,
  SupportedAlgorithm,
} from '@ethersproject/sha2';

import * as pkcs7 from './pkcs7';
import { arrayToBuffer } from '../helpers/util';

export async function fallbackCreateHmac(
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  const result = computeHmac(SupportedAlgorithm.sha256, key, data);
  return Buffer.from(result);
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

export async function fallbackSha256(msg: Buffer | string): Promise<Buffer> {
  const enc = isHexString(msg) ? 'hex' : undefined;
  const buf = typeof msg === 'string' ? Buffer.from(msg, enc) : msg;
  const hash = sha256(buf);
  return Buffer.from(arrayify(hash));
}

export async function fallbackSha512(msg: Buffer | string): Promise<Buffer> {
  const enc = isHexString(msg) ? 'hex' : undefined;
  const buf = typeof msg === 'string' ? Buffer.from(msg, enc) : msg;
  const hash = sha512(buf);
  return Buffer.from(arrayify(hash));
}
