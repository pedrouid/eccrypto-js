import { getAes } from './aes';
import { derive } from './ecdh';
import { getPublic } from './ecdsa';
import { randomBytes } from './random';
import { hashSharedKey, hmacSha256Sign, hmacSha256Verify } from './sha2';
import { Encrypted, PreEncryptOpts } from './types';
import { assert, isValidPrivateKey } from './validators';

export async function encrypt(
  publicKeyTo: Buffer,
  msg: Buffer,
  opts?: PreEncryptOpts
) {
  opts = (opts || {}) as PreEncryptOpts;
  // Tmp variables to save context from flat promises;
  let iv: Buffer;
  let ephemPublicKey: Buffer;
  let ciphertext: Buffer;
  let macKey: Buffer;
  var ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32);
  // There is a very unlikely possibility that it is not a valid key
  while (!isValidPrivateKey(ephemPrivateKey)) {
    ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32);
  }
  ephemPublicKey = getPublic(ephemPrivateKey);
  const sharedKey = await derive(ephemPrivateKey, publicKeyTo);
  const hash = await hashSharedKey(sharedKey);

  iv = opts?.iv || randomBytes(16);
  let encryptionKey = hash.slice(0, 32);
  macKey = Buffer.from(hash.slice(32));
  const aesCbcEncrypt = getAes('encrypt');
  const data = await aesCbcEncrypt(iv, Buffer.from(encryptionKey), msg);

  ciphertext = data;
  let dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
  const mac = await hmacSha256Sign(macKey, dataToMac);

  return {
    iv: iv,
    ephemPublicKey: ephemPublicKey,
    ciphertext: ciphertext,
    mac: mac,
  };
}

export async function decrypt(privateKey: Buffer, opts: Encrypted) {
  // Tmp variable to save context from flat promises;
  let encryptionKey: Buffer;
  const sharedKey = await derive(privateKey, opts.ephemPublicKey);
  const hash = await hashSharedKey(sharedKey);

  encryptionKey = Buffer.from(hash.slice(0, 32));
  let macKey = hash.slice(32);
  let dataToMac = Buffer.concat([
    opts.iv,
    opts.ephemPublicKey,
    opts.ciphertext,
  ]);
  const macGood = await hmacSha256Verify(
    Buffer.from(macKey),
    dataToMac,
    opts.mac
  );

  assert(macGood, 'Bad MAC');
  const aesCbcDecrypt = getAes('decrypt');
  const msg = await aesCbcDecrypt(opts.iv, encryptionKey, opts.ciphertext);

  return Buffer.from(new Uint8Array(msg));
}
