import { getAes } from './aes';
import { derive } from './ecdh';
import { getPublic } from './ecdsa';
import { randomBytes } from './random';
import { hashSharedKey } from './sha2';
import { getHmac } from './hmac';
import { Encrypted, PreEncryptOpts } from './types';
import { assert, isValidPrivateKey } from './validators';
import { ENCRYPT_OP, SIGN_OP, VERIFY_OP, DECRYPT_OP } from './constants';

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
): Promise<Encrypted> {
  const { ephemPrivateKey, ephemPublicKey } = await handleEphemKeyPair(opts);
  const { encryptionKey, macKey } = await getEncryptionKeys(
    ephemPrivateKey,
    publicKeyTo
  );
  const iv: Buffer = opts?.iv || randomBytes(16);
  const aesCbcEncrypt = getAes(ENCRYPT_OP);
  const ciphertext = await aesCbcEncrypt(iv, encryptionKey, msg);
  const dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
  const hmacSha256Sign = getHmac(SIGN_OP);
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
  const hmacSha256Verify = getHmac(VERIFY_OP);
  const macTest = await hmacSha256Verify(macKey, dataToMac, mac);
  assert(macTest as boolean, 'Bad MAC');
  const aesCbcDecrypt = getAes(DECRYPT_OP);
  const msg = await aesCbcDecrypt(opts.iv, encryptionKey, opts.ciphertext);
  return msg;
}
