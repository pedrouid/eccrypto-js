import { aesCbcEncrypt, aesCbcDecrypt } from './aes';
import { derive } from './ecdh';
import { getPublic, decompress, compress } from './ecdsa';
import { hmacSha256Sign, hmacSha256Verify } from './hmac';
import { randomBytes } from './random';
import { sha512 } from './sha2';

import { Encrypted, PreEncryptOpts } from './helpers/types';
import { assert, isValidPrivateKey } from './helpers/validators';
import { isCompressed, concatBuffers } from './helpers/util';
import {
  ZERO_LENGTH,
  KEY_LENGTH,
  IV_LENGTH,
  MAC_LENGTH,
  PREFIXED_KEY_LENGTH,
} from './helpers/constants';

async function getEncryptionKeys(privateKey: Buffer, publicKey: Buffer) {
  publicKey = isCompressed(publicKey) ? decompress(publicKey) : publicKey;
  const sharedKey = await derive(privateKey, publicKey);
  const hash = await sha512(sharedKey);
  const encryptionKey = Buffer.from(hash.slice(ZERO_LENGTH, KEY_LENGTH));
  const macKey = Buffer.from(hash.slice(KEY_LENGTH));
  return { encryptionKey, macKey };
}

async function getEphemKeyPair(opts?: Partial<PreEncryptOpts>) {
  let ephemPrivateKey = opts?.ephemPrivateKey || randomBytes(KEY_LENGTH);
  while (!isValidPrivateKey(ephemPrivateKey)) {
    ephemPrivateKey = opts?.ephemPrivateKey || randomBytes(KEY_LENGTH);
  }
  const ephemPublicKey = getPublic(ephemPrivateKey);
  return { ephemPrivateKey, ephemPublicKey };
}

export async function encrypt(
  publicKeyTo: Buffer,
  msg: Buffer,
  opts?: Partial<PreEncryptOpts>
): Promise<Encrypted> {
  const { ephemPrivateKey, ephemPublicKey } = await getEphemKeyPair(opts);
  const { encryptionKey, macKey } = await getEncryptionKeys(
    ephemPrivateKey,
    publicKeyTo
  );
  const iv = opts?.iv || randomBytes(IV_LENGTH);
  const ciphertext = await aesCbcEncrypt(iv, encryptionKey, msg);
  const dataToMac = concatBuffers(iv, ephemPublicKey, ciphertext);
  const mac = await hmacSha256Sign(macKey, dataToMac);
  return { iv, ephemPublicKey, ciphertext, mac: mac };
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
  const dataToMac = concatBuffers(iv, ephemPublicKey, ciphertext);
  const macTest = await hmacSha256Verify(macKey, dataToMac, mac);
  assert(macTest, 'Bad MAC');
  const msg = await aesCbcDecrypt(opts.iv, encryptionKey, opts.ciphertext);
  return msg;
}

export function serialize(opts: Encrypted): Buffer {
  const ephemPublicKey = compress(opts.ephemPublicKey);
  return concatBuffers(opts.iv, ephemPublicKey, opts.mac, opts.ciphertext);
}

export function deserialize(buf: Buffer): Encrypted {
  const slice0 = ZERO_LENGTH;
  const slice1 = IV_LENGTH;
  const slice2 = IV_LENGTH + PREFIXED_KEY_LENGTH;
  const slice3 = IV_LENGTH + PREFIXED_KEY_LENGTH + MAC_LENGTH;
  const slice4 = buf.length;
  return {
    iv: buf.slice(slice0, slice1),
    ephemPublicKey: decompress(buf.slice(slice1, slice2)),
    mac: buf.slice(slice2, slice3),
    ciphertext: buf.slice(slice3, slice4),
  };
}
