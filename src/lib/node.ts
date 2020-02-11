import {
  HMAC_NODE_ALGO,
  AES_NODE_ALGO,
  SHA512_NODE_ALGO,
  SHA256_NODE_ALGO,
} from '../helpers/constants';
import { concatBuffers } from '../helpers/util';

const nodeCrypto = require('crypto');

export function isNode() {
  return !!nodeCrypto;
}

export function nodeRandomBytes(length: number): Buffer {
  return nodeCrypto.randomBytes(length);
}

export async function nodeAesEncrypt(
  iv: Buffer,
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  const cipher = nodeCrypto.createCipheriv(AES_NODE_ALGO, key, iv);
  return concatBuffers(cipher.update(data), cipher.final());
}

export async function nodeAesDecrypt(
  iv: Buffer,
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  const decipher = nodeCrypto.createDecipheriv(AES_NODE_ALGO, key, iv);
  return concatBuffers(decipher.update(data), decipher.final());
}

export async function nodeCreateHmac(
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  const hmac = nodeCrypto.createHmac(HMAC_NODE_ALGO, Buffer.from(key));
  return hmac.update(data).digest();
}

export async function nodeSha256(data: Buffer) {
  const hash = nodeCrypto.createHash(SHA256_NODE_ALGO);
  return hash.update(data).digest();
}

export async function nodeSha512(data: Buffer) {
  const hash = nodeCrypto.createHash(SHA512_NODE_ALGO);
  return hash.update(data).digest();
}
