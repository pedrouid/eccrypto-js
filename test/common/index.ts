import crypto from 'crypto';
import * as eccryptoJS from '../../src';

export function testGenerateKeyPair(lib: eccryptoJS.IEccrypto = eccryptoJS) {
  const keyPair = lib.generateKeyPair();
  expect(keyPair.privateKey).toBeTruthy();
  expect(keyPair.publicKey).toBeTruthy();
  return keyPair;
}

export async function testSign(
  privateKey: Buffer,
  lib: eccryptoJS.IEccrypto = eccryptoJS
) {
  const str = 'message to sign';
  const hash = lib.sha256
    ? await lib.sha256(str)
    : crypto
        .createHash('sha256')
        .update(str)
        .digest()
        .toString('hex');
  const msg = Buffer.from(hash, 'hex');
  const sig = await lib.sign(privateKey, msg);
  return { str, msg, sig };
}

export async function testSharedKeys(lib: eccryptoJS.IEccrypto = eccryptoJS) {
  const keyPairA = testGenerateKeyPair();
  const keyPairB = testGenerateKeyPair();
  const sharedKey1 = await lib.derive(keyPairA.privateKey, keyPairB.publicKey);

  const sharedKey2 = await lib.derive(keyPairB.privateKey, keyPairA.publicKey);
  return { sharedKey1, sharedKey2 };
}

export async function testEncrypt(
  publicKey: Buffer,
  opts?: any,
  lib: eccryptoJS.IEccrypto = eccryptoJS
) {
  const str = 'message to sign';
  const msg = lib.utf8ToBuffer ? lib.utf8ToBuffer(str) : Buffer.from(str);
  const encrypted = await lib.encrypt(publicKey, msg, opts);
  return { str, msg, encrypted };
}

export async function prettyPrint(name: string, obj: any) {
  const displayObject: any = {};
  Object.keys(obj).forEach((key: string) => {
    const value = Buffer.isBuffer(obj[key])
      ? obj[key].toString('hex')
      : obj[key];
    displayObject[key] = value;
  });
  console.log(name, JSON.stringify(displayObject, null, 2));
}
