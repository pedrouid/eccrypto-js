import { getAes } from './aes';
import { derive } from './ecdh';
import { getPublic } from './ecdsa';
import { randomBytes } from './random';
import { hashSharedKey, hmacSha256Sign, hmacSha256Verify } from './sha2';
import { Encrypted, PreEncryptOpts } from './types';
import { assert, isValidPrivateKey } from './validators';

async function getEncryptionKeys(privateKey: Buffer, publicKey: Buffer) {
  const sharedKey: Buffer = await derive(privateKey, publicKey);
  const hash: Uint8Array = await hashSharedKey(sharedKey);
  const encryptionKey: Buffer = Buffer.from(hash.slice(0, 32));
  const macKey: Buffer = Buffer.from(hash.slice(32));
  return { encryptionKey, macKey };
}

async function handleEphemKeyPair(opts?: PreEncryptOpts) {
  opts = (opts || {}) as PreEncryptOpts;
  let ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32);
  while (!isValidPrivateKey(ephemPrivateKey)) {
    ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32);
  }
  const ephemPublicKey: Buffer = getPublic(ephemPrivateKey);
  return { ephemPrivateKey, ephemPublicKey };
}


export async function encrypt(
  publicKeyTo: Buffer,
  msg: Buffer,
  opts?: PreEncryptOpts
) {
  const { ephemPrivateKey, ephemPublicKey } = await handleEphemKeyPair(opts);
  const { encryptionKey, macKey } = await getEncryptionKeys(
    ephemPrivateKey,
    publicKeyTo
  );
  const iv: Buffer = opts?.iv || randomBytes(16);
  const aesCbcEncrypt = getAes('encrypt');
  const ciphertext: Buffer = await aesCbcEncrypt(iv, Buffer.from(encryptionKey), msg);
  const dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
  const mac = await hmacSha256Sign(macKey, dataToMac);
  return { iv, ephemPublicKey, ciphertext, mac };
}

export async function decrypt(privateKey: Buffer, opts: Encrypted) {
  const { ephemPublicKey, iv, mac, ciphertext } = opts;
  const { encryptionKey, macKey } = await getEncryptionKeys(
    privateKey,
    ephemPublicKey
  );

  const dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
  const macTest = await hmacSha256Verify(macKey, dataToMac, mac);
  assert(macTest, 'Bad MAC');
  const aesCbcDecrypt = getAes('decrypt');
  const msg = await aesCbcDecrypt(opts.iv, encryptionKey, opts.ciphertext);
  return msg;
}
