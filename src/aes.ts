import aesJs from 'aes-js';
// @ts-ignore
import pkcs7 from 'pkcs7';

// @ts-ignore
const browserCrypto = global.crypto || global.msCrypto || {};
const subtle = browserCrypto.subtle || browserCrypto.webkitSubtle;

const nodeCrypto = require('crypto');

export function getAes(op: string) {
  return async (iv: Buffer, key: Buffer, data: Buffer) => {
    if (subtle) {
      const importAlgorithm = { name: 'AES-CBC' };
      const cryptoKey = await subtle.importKey(
        'raw',
        key,
        importAlgorithm,
        false,
        [op]
      );
      const encAlgorithm = { ...importAlgorithm, iv: iv };
      const result = subtle[op](encAlgorithm, cryptoKey, data);
      return Buffer.from(new Uint8Array(result));
    } else if (nodeCrypto) {
      if (op === 'encrypt') {
        const cipher = nodeCrypto.createCipheriv('aes-256-cbc', key, iv);
        cipher.update(data);
        return cipher.final();
      } else if (op === 'decrypt') {
        const decipher = nodeCrypto.createDecipheriv('aes-256-cbc', key, iv);
        decipher.update(data);
        return decipher.final();
      }
    } else {
      if (op === 'encrypt') {
        const aesCbc = new aesJs.ModeOfOperation.cbc(key, iv);
        const encryptedBytes = aesCbc.encrypt(pkcs7.pad(data));
        return Buffer.from(encryptedBytes);
      } else if (op === 'decrypt') {
        const aesCbc = new aesJs.ModeOfOperation.cbc(key, iv);
        const encryptedBytes = aesCbc.decrypt(data);
        const result: Buffer = pkcs7.unpad(Buffer.from(encryptedBytes));
        return result;
      }
    }
  };
}
