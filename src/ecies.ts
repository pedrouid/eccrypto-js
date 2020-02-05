import { aesCbcEncrypt, aesCbcDecrypt } from './aes';
import { derive } from './ecdh';
import { getPublic } from './ecdsa';
import { randomBytes } from './random';
import { hashSharedKey, hmacSha256Sign, hmacSha256Verify } from './sha2';
import { Encrypted, PreEncryptOpts } from './types';
import { assert, isValidPrivateKey } from './validators';

export async function generateEncryptionAndMacKey(
  privateKey: Buffer,
  publicKey: Buffer
) {
  const sharedKey: Buffer = await derive(privateKey, publicKey);
  const hash: Uint8Array = await hashSharedKey(sharedKey);
  const encryptionKey: Buffer = Buffer.from(hash.slice(0, 32));
  const macKey: Buffer = Buffer.from(hash.slice(32));
  return { encryptionKey, macKey };
}

export async function encrypt(
  publicKeyTo: Buffer,
  msg: Buffer,
  opts?: PreEncryptOpts
) {
  opts = (opts || {}) as PreEncryptOpts;
  let ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32);
  // There is a very unlikely possibility that it is not a valid key
  while (!isValidPrivateKey(ephemPrivateKey)) {
    ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32);
  }
  const ephemPublicKey: Buffer = getPublic(ephemPrivateKey);
  const { encryptionKey, macKey } = await generateEncryptionAndMacKey(
    ephemPrivateKey,
    publicKeyTo
  );
  const iv: Buffer = opts?.iv || randomBytes(16);
  const data: Buffer = await aesCbcEncrypt(iv, encryptionKey, msg);

  const ciphertext = data;
  const dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
  const mac = await hmacSha256Sign(macKey, dataToMac);

  return {
    iv: iv,
    ephemPublicKey: ephemPublicKey,
    ciphertext: ciphertext,
    mac: mac,
  };
}

export async function decrypt(privateKey: Buffer, opts: Encrypted) {
  const { encryptionKey, macKey } = await generateEncryptionAndMacKey(
    privateKey,
    opts.ephemPublicKey
  );
  const dataToMac = Buffer.concat([
    opts.iv,
    opts.ephemPublicKey,
    opts.ciphertext,
  ]);
  const macGood = await hmacSha256Verify(macKey, dataToMac, opts.mac);

  assert(macGood, 'Bad MAC');
  const msg = await aesCbcDecrypt(opts.iv, encryptionKey, opts.ciphertext);

  return Buffer.from(new Uint8Array(msg));
}
