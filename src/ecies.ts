import { aesCbcEncrypt, aesCbcDecrypt } from './aes';
import { derive } from './ecdh';
import { getPublic } from './ecdsa';
import { hmacSha256Sign, hmacSha256Verify } from './hmac';
import { randomBytes } from './random';
import { sha512 } from './sha2';

import { Encrypted, PreEncryptOpts } from './helpers/types';
import { assert, isValidPrivateKey } from './helpers/validators';

async function getEncryptionKeys(privateKey: Buffer, publicKey: Buffer) {
  const sharedKey = await derive(privateKey, publicKey);
  const hash = await sha512(sharedKey);
  const encryptionKey = Buffer.from(hash.slice(0, 32));
  const macKey = Buffer.from(hash.slice(32));
  return { encryptionKey, macKey };
}

async function handleEphemKeyPair(opts?: PreEncryptOpts) {
  opts = (opts || {}) as PreEncryptOpts;
  let ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32);
  while (!isValidPrivateKey(ephemPrivateKey)) {
    ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32);
  }
  const ephemPublicKey = getPublic(ephemPrivateKey);
  return { ephemPrivateKey, ephemPublicKey };
}

export async function encrypt(
  publicKeyTo: Buffer,
  msg: Buffer,
  opts?: PreEncryptOpts
): Promise<Encrypted> {
  const { ephemPrivateKey, ephemPublicKey } = await handleEphemKeyPair(opts);
  const { encryptionKey, macKey } = await getEncryptionKeys(
    ephemPrivateKey,
    publicKeyTo
  );
  const iv = opts?.iv || randomBytes(16);
  const ciphertext = await aesCbcEncrypt(iv, encryptionKey, msg);
  const dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
  const mac = await hmacSha256Sign(macKey, dataToMac);
  return { iv, ephemPublicKey, ciphertext, mac: mac as Buffer };
}

export async function decrypt(
  privateKey: Buffer,
  opts: Encrypted
): Promise<Buffer> {
  const { ephemPublicKey, iv, mac, ciphertext } = opts;
  const { encryptionKey, macKey } = await getEncryptionKeys(
    privateKey,
    ephemPublicKey
  );
  const dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
  const macTest = await hmacSha256Verify(macKey, dataToMac, mac);
  assert(macTest as boolean, 'Bad MAC');
  const msg = await aesCbcDecrypt(opts.iv, encryptionKey, opts.ciphertext);
  return msg;
}
