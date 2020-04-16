import aesJs from 'aes-js';
import randomBytes from 'randombytes';
import * as hash from 'hash.js';

import * as pkcs7 from './pkcs7';

import { SHA256_NODE_ALGO, HEX_ENC, SHA512_NODE_ALGO } from '../constants';
import { arrayToBuffer, hexToBuffer } from '../helpers';

export function fallbackRandomBytes(length: number): Buffer {
  return randomBytes(length);
}

export function fallbackAesEncrypt(iv: Buffer, key: Buffer, data: Buffer) {
  const aesCbc = new aesJs.ModeOfOperation.cbc(key, iv);
  const padded = arrayToBuffer(pkcs7.pad(data));
  const encryptedBytes = aesCbc.encrypt(padded);
  return Buffer.from(encryptedBytes);
}

export function fallbackAesDecrypt(iv: Buffer, key: Buffer, data: Buffer) {
  const aesCbc = new aesJs.ModeOfOperation.cbc(key, iv);
  const encryptedBytes = aesCbc.decrypt(data);
  const padded = Buffer.from(encryptedBytes);
  const result = arrayToBuffer(pkcs7.unpad(padded));
  return result;
}

export function fallbackHmacSha256Sign(key: Buffer, data: Buffer): Buffer {
  const result = hash
    .hmac((hash as any)[SHA256_NODE_ALGO], key)
    .update(data)
    .digest(HEX_ENC);
  return hexToBuffer(result);
}

export function fallbackHmacSha512Sign(key: Buffer, data: Buffer): Buffer {
  const result = hash
    .hmac((hash as any)[SHA512_NODE_ALGO], key)
    .update(data)
    .digest(HEX_ENC);
  return hexToBuffer(result);
}

export function fallbackSha256(msg: Buffer): Buffer {
  const result = hash
    .sha256()
    .update(msg)
    .digest(HEX_ENC);
  return hexToBuffer(result);
}

export function fallbackSha512(msg: Buffer): Buffer {
  const result = hash
    .sha512()
    .update(msg)
    .digest(HEX_ENC);
  return hexToBuffer(result);
}

export function fallbackRipemd160(msg: Buffer): Buffer {
  const result = hash
    .ripemd160()
    .update(msg)
    .digest(HEX_ENC);
  return hexToBuffer(result);
}
