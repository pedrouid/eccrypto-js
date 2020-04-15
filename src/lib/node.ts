import {
  HMAC_NODE_ALGO,
  AES_NODE_ALGO,
  SHA512_NODE_ALGO,
  SHA256_NODE_ALGO,
} from '../helpers/constants';
import { concatBuffers } from '../helpers/util';

export function requireNodeCrypto() {
  let nodeCrypto;
  try {
    nodeCrypto = require('crypto');
  } catch (e) {
    // do nothing
  }
  return nodeCrypto;
}

export function getNodeCrypto() {
  const nodeCrypto = requireNodeCrypto();
  if (!nodeCrypto) {
    throw new Error('NodeJS Crypto module not available');
  }
  return nodeCrypto;
}

export function isNode() {
  return !!requireNodeCrypto();
}

export function nodeRandomBytes(length: number): Buffer {
  return getNodeCrypto().randomBytes(length);
}

export async function nodeAesEncrypt(
  iv: Buffer,
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  const cipher = getNodeCrypto().createCipheriv(AES_NODE_ALGO, key, iv);
  return concatBuffers(cipher.update(data), cipher.final());
}

export async function nodeAesDecrypt(
  iv: Buffer,
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  const decipher = getNodeCrypto().createDecipheriv(AES_NODE_ALGO, key, iv);
  return concatBuffers(decipher.update(data), decipher.final());
}

export async function nodeCreateHmac(
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  const hmac = getNodeCrypto().createHmac(HMAC_NODE_ALGO, Buffer.from(key));
  return hmac.update(data).digest();
}

export async function nodeSha256(data: Buffer) {
  const hash = getNodeCrypto().createHash(SHA256_NODE_ALGO);
  return hash.update(data).digest();
}

export async function nodeSha512(data: Buffer) {
  const hash = getNodeCrypto().createHash(SHA512_NODE_ALGO);
  return hash.update(data).digest();
}
