export const ENCRYPT_OP = 'encrypt';
export const DECRYPT_OP = 'decrypt';

export const SIGN_OP = 'sign';
export const VERIFY_OP = 'verify';

export const AES_LENGTH = 256;
export const HMAC_LENGTH = 256;

export const AES_BROWSER_ALGO = 'AES-CBC';
export const HMAC_BROWSER_ALGO = `SHA-${AES_LENGTH}`;
export const HMAC_BROWSER = 'HMAC';
export const SHA256_BROWSER_ALGO = 'SHA-256';
export const SHA512_BROWSER_ALGO = 'SHA-512';

export const AES_NODE_ALGO = `aes-${AES_LENGTH}-cbc`;
export const HMAC_NODE_ALGO = `sha${HMAC_LENGTH}`;
export const SHA256_NODE_ALGO = 'sha256';
export const SHA512_NODE_ALGO = 'sha512';

export const KEY_LENGTH = 32;
export const IV_LENGTH = 16;

export const EMPTY_BUFFER = Buffer.from(new Uint8Array(0));
export const EC_GROUP_ORDER = Buffer.from(
  'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
  'hex'
);
export const ZERO32 = Buffer.alloc(32, 0);
