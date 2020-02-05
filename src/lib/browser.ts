import {
  ENCRYPT_OP,
  DECRYPT_OP,
  SIGN_OP,
  VERIFY_OP,
  AES_BROWSER_ALGO,
  AES_LENGTH,
  HMAC_BROWSER_ALGO,
  HMAC_BROWSER,
  HMAC_LENGTH,
  SHA256_BROWSER_ALGO,
  SHA512_BROWSER_ALGO,
} from '../helpers/constants';

// @ts-ignore
const browserCrypto = global.crypto || global.msCrypto || {};
const subtle: SubtleCrypto = browserCrypto.subtle || browserCrypto.webkitSubtle;

export function isBrowser() {
  return !!subtle;
}

export async function browserImportKey(
  buffer: Buffer,
  type: string = AES_BROWSER_ALGO
): Promise<CryptoKey> {
  const algo: AesKeyAlgorithm | HmacImportParams =
    type === AES_BROWSER_ALGO
      ? { length: AES_LENGTH, name: AES_BROWSER_ALGO }
      : {
          hash: { name: HMAC_BROWSER_ALGO },
          name: HMAC_BROWSER,
        };
  const ops =
    type === AES_BROWSER_ALGO ? [ENCRYPT_OP, DECRYPT_OP] : [SIGN_OP, VERIFY_OP];
  const cryptoKey = await subtle.importKey('raw', buffer, algo, true, ops);
  return cryptoKey;
}

export async function browserAesEncrypt(
  iv: Buffer,
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  const cryptoKey = await browserImportKey(key, AES_BROWSER_ALGO);
  const result = await subtle.encrypt(
    {
      iv,
      name: AES_BROWSER_ALGO,
    },
    cryptoKey,
    data
  );
  return Buffer.from(result);
}

export async function browserAesDecrypt(
  iv: Buffer,
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  const cryptoKey = await browserImportKey(key, AES_BROWSER_ALGO);
  const result = await subtle.decrypt(
    {
      iv,
      name: AES_BROWSER_ALGO,
    },
    cryptoKey,
    data
  );
  return Buffer.from(result);
}

export async function browserCreateHmac(
  key: Buffer,
  data: Buffer
): Promise<Buffer> {
  const cryptoKey = await browserImportKey(key, HMAC_BROWSER);
  const signature = await subtle.sign(
    {
      length: HMAC_LENGTH,
      name: HMAC_BROWSER,
    },
    cryptoKey,
    data
  );
  return Buffer.from(signature);
}

export async function browserSha256(data: Buffer): Promise<Buffer> {
  const result = await subtle.digest(
    {
      name: SHA256_BROWSER_ALGO,
    },
    data
  );
  return Buffer.from(result);
}

export async function browserSha512(data: Buffer): Promise<Buffer> {
  const result = await subtle.digest(
    {
      name: SHA512_BROWSER_ALGO,
    },
    data
  );
  return Buffer.from(result);
}
