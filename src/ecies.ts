import { aesCbcEncrypt, aesCbcDecrypt } from './aes';
import { derive } from './ecdh';
import { getPublic } from './ecdsa';
import { randomBytes } from './random';
import { sha512, hmacSha256Sign, hmacSha256Verify } from './sha2';
import { Encrypted } from './types';
import { assert } from './validators';

export function encrypt(publicKeyTo: Buffer, msg: Buffer, opts: Encrypted) {
  opts = opts || {};
  // Tmp variables to save context from flat promises;
  let iv: Buffer;
  let ephemPublicKey: Buffer;
  let ciphertext: Buffer;
  let macKey: Buffer;
  return new Promise(async resolve => {
    let ephemPrivateKey = randomBytes(32);
    // There is a very unlikely possibility that it is not a valid key
    ephemPublicKey = getPublic(ephemPrivateKey);
    resolve(derive(ephemPrivateKey, publicKeyTo));
  })
    .then((Px: any) => sha512(Px))
    .then(hash => {
      iv = opts.iv || randomBytes(16);
      let encryptionKey = hash.slice(0, 32);
      macKey = Buffer.from(hash.slice(32));
      return aesCbcEncrypt(iv, Buffer.from(encryptionKey), msg);
    })
    .then(data => {
      ciphertext = data;
      let dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
      return hmacSha256Sign(macKey, dataToMac);
    })
    .then(mac => {
      return {
        iv: iv,
        ephemPublicKey: ephemPublicKey,
        ciphertext: ciphertext,
        mac: mac,
      };
    });
}

export function decrypt(privateKey: Buffer, opts: Encrypted) {
  // Tmp variable to save context from flat promises;
  let encryptionKey: Buffer;
  return derive(privateKey, opts.ephemPublicKey)
    .then((Px: any) => sha512(Px))
    .then(hash => {
      encryptionKey = Buffer.from(hash.slice(0, 32));
      let macKey = hash.slice(32);
      let dataToMac = Buffer.concat([
        opts.iv,
        opts.ephemPublicKey,
        opts.ciphertext,
      ]);
      return hmacSha256Verify(Buffer.from(macKey), dataToMac, opts.mac);
    })
    .then(macGood => {
      assert(macGood, 'Bad MAC');
      return aesCbcDecrypt(opts.iv, encryptionKey, opts.ciphertext);
    })
    .then(msg => {
      return Buffer.from(new Uint8Array(msg));
    });
}
