import { HMAC_NODE_ALGO, AES_NODE_ALGO } from './constants';

const nodeCrypto = require('crypto');

export function isNode() {
  return !!nodeCrypto;
}

export async function nodeCreateHmac(
  key: Buffer,
  msg: Buffer
): Promise<Buffer> {
  const hmac = nodeCrypto.createHmac(HMAC_NODE_ALGO, Buffer.from(key));
  hmac.update(msg);
  const result = hmac.digest();
  return result;
}

export async function nodeAesEncrypt(
  iv: Buffer,
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  const cipher = nodeCrypto.createCipheriv(AES_NODE_ALGO, key, iv);
  cipher.update(data);
  return cipher.final();
}

export async function nodeAesDecrypt(
  iv: Buffer,
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  const decipher = nodeCrypto.createDecipheriv(AES_NODE_ALGO, key, iv);
  decipher.update(data);
  return decipher.final();
}
