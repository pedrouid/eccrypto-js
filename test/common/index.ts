import crypto from 'crypto';
import * as eccryptoJS from '../../src';

export function testGenerateKeyPair(lib: any = eccryptoJS) {
  const keyPair = lib.generateKeyPair();
  expect(keyPair.privateKey).toBeTruthy();
  expect(keyPair.publicKey).toBeTruthy();
  return keyPair;
}

export async function testSign(privateKey: Buffer, lib: any = eccryptoJS) {
  const str = 'message to sign';
  const hash = lib.sha256
    ? await lib.sha256(str)
    : crypto
        .createHash('sha256')
        .update(str)
        .digest();
  const msg = Buffer.from(hash, 'hex');
  const sig = await lib.sign(privateKey, msg);
  return { str, msg, sig };
}

export async function testSharedKeys(lib: any = eccryptoJS) {
  const keyPairA = testGenerateKeyPair();
  const keyPairB = testGenerateKeyPair();
  const sharedKey1 = await lib.derive(keyPairA.privateKey, keyPairB.publicKey);

  const sharedKey2 = await lib.derive(keyPairB.privateKey, keyPairA.publicKey);
  return { sharedKey1, sharedKey2 };
}

export async function testEncrypt(publicKey: Buffer, lib: any = eccryptoJS) {
  const str = 'message to sign';
  const msg = lib.utf8ToBuffer ? lib.utf8ToBuffer(str) : Buffer.from(str);
  const encrypted = await lib.encrypt(publicKey, msg);
  return { str, msg, encrypted };
}
