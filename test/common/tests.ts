import crypto from 'crypto';
import * as eccryptoJS from '../../src';
import * as nodeLib from '../../src/lib/node';
import { TEST_MESSAGE_STR } from './constants';

export function testGenerateKeyPair(lib: eccryptoJS.IEccrypto = eccryptoJS) {
  const keyPair = lib.generateKeyPair();
  expect(keyPair.privateKey).toBeTruthy();
  expect(keyPair.publicKey).toBeTruthy();
  return keyPair;
}

export async function testSha2(
  msg: Buffer,
  algo: string,
  lib: eccryptoJS.IEccrypto = eccryptoJS
) {
  // @ts-ignore
  const shaMethod = lib[algo];
  const hash: Buffer = shaMethod
    ? await shaMethod(msg)
    : crypto
        .createHash(algo)
        .update(msg)
        .digest();

  return hash;
}

export function testRandomBytes(
  length: number,
  lib: eccryptoJS.IEccrypto = eccryptoJS
) {
  const result = lib.randomBytes
    ? lib.randomBytes(length)
    : crypto.randomBytes(length);
  return result;
}

export function testAesEncrypt(
  iv: Buffer,
  key: Buffer,
  data: Buffer,
  lib: eccryptoJS.IEccrypto = eccryptoJS
) {
  return lib.aesCbcEncrypt
    ? lib.aesCbcEncrypt(iv, key, data)
    : nodeLib.nodeAesEncrypt(iv, key, data);
}

export function testAesDecrypt(
  iv: Buffer,
  key: Buffer,
  data: Buffer,
  lib: eccryptoJS.IEccrypto = eccryptoJS
) {
  return lib.aesCbcDecrypt
    ? lib.aesCbcDecrypt(iv, key, data)
    : nodeLib.nodeAesDecrypt(iv, key, data);
}

export async function testHmacSign(
  key: Buffer,
  data: Buffer,
  lib: eccryptoJS.IEccrypto = eccryptoJS
) {
  return lib.hmacSha256Sign
    ? lib.hmacSha256Sign(key, data)
    : nodeLib.nodeHmacSha256Sign(key, data);
}

export function testHmacVerify(
  key: Buffer,
  data: Buffer,
  sig: Buffer,
  lib: eccryptoJS.IEccrypto = eccryptoJS
) {
  async function nodeHmacVerify(key: Buffer, data: Buffer, sig: Buffer) {
    const expectedSig = nodeLib.nodeHmacSha256Sign(key, data);
    return eccryptoJS.equalConstTime(expectedSig, sig);
  }
  return lib.hmacSha256Verify
    ? lib.hmacSha256Verify(key, data, sig)
    : nodeHmacVerify(key, data, sig);
}

export async function getTestMessageToSign(
  str = TEST_MESSAGE_STR,
  lib: eccryptoJS.IEccrypto = eccryptoJS
) {
  const data = Buffer.from(str);
  const msg = await testSha2(data, eccryptoJS.SHA256_NODE_ALGO, lib);
  return { str, msg };
}

export async function testSign(
  privateKey: Buffer,
  rsvSig = false,
  lib: eccryptoJS.IEccrypto = eccryptoJS
) {
  const { str, msg } = await getTestMessageToSign(undefined, lib);
  const sig = await lib.sign(privateKey, msg, rsvSig);
  return { str, msg, sig };
}

export async function testSharedKeys(lib: eccryptoJS.IEccrypto = eccryptoJS) {
  const keyPairA = testGenerateKeyPair();
  const keyPairB = testGenerateKeyPair();
  const sharedKey1 = await lib.derive(keyPairA.privateKey, keyPairB.publicKey);

  const sharedKey2 = await lib.derive(keyPairB.privateKey, keyPairA.publicKey);
  return { sharedKey1, sharedKey2 };
}

export async function getTestMessageToEncrypt(
  str = TEST_MESSAGE_STR,
  lib: eccryptoJS.IEccrypto = eccryptoJS
) {
  const msg = lib.utf8ToBuffer ? lib.utf8ToBuffer(str) : Buffer.from(str);
  return { str, msg };
}

export async function testEncrypt(
  publicKey: Buffer,
  opts?: Partial<eccryptoJS.PreEncryptOpts>,
  lib: eccryptoJS.IEccrypto = eccryptoJS
) {
  const { str, msg } = await getTestMessageToEncrypt(undefined, lib);
  const encrypted = await lib.encrypt(publicKey, msg, opts);
  return { str, msg, encrypted };
}

export async function testEcies(
  publicKeyTo: Buffer,
  opts?: Partial<eccryptoJS.PreEncryptOpts>,
  lib: eccryptoJS.IEccrypto = eccryptoJS
) {
  const { str, msg } = await getTestMessageToEncrypt(undefined, lib);

  const ephemPrivateKey = opts?.ephemPrivateKey || testRandomBytes(32, lib);
  const ephemPublicKey = eccryptoJS.getPublic(ephemPrivateKey);

  const sharedKey = await lib.derive(ephemPrivateKey, publicKeyTo);
  const hash = await testSha2(msg, eccryptoJS.SHA512_NODE_ALGO, lib);
  const encryptionKey = Buffer.from(hash.slice(0, 32));
  const macKey = Buffer.from(hash.slice(32));
  const iv = opts?.iv || testRandomBytes(16, lib);
  const ciphertext = await testAesEncrypt(iv, encryptionKey, msg, lib);
  const dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
  const mac = await testHmacSign(macKey, dataToMac, lib);

  return {
    str,
    msg,
    ephemPrivateKey,
    ephemPublicKey,
    sharedKey,
    hash,
    encryptionKey,
    macKey,
    iv,
    ciphertext,
    dataToMac,
    mac,
  };
}
