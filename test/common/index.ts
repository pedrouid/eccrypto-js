import * as eccryptoJS from '../../src';

export function testGenerateKeyPair() {
  const keyPair = eccryptoJS.generateKeyPair();
  expect(keyPair.privateKey).toBeTruthy();
  expect(keyPair.publicKey).toBeTruthy();
  return keyPair;
}

export async function testSign(privateKey: Buffer) {
  const str = 'message to sign';
  const hash = await eccryptoJS.sha256(str);
  const msg = Buffer.from(hash, 'hex');
  const sig = await eccryptoJS.sign(privateKey, msg);
  return { str, msg, sig };
}

export async function testSharedKeys() {
  const keyPairA = testGenerateKeyPair();
  const keyPairB = testGenerateKeyPair();
  const sharedKey1 = await eccryptoJS.derive(
    keyPairA.privateKey,
    keyPairB.publicKey
  );

  const sharedKey2 = await eccryptoJS.derive(
    keyPairB.privateKey,
    keyPairA.publicKey
  );
  return { sharedKey1, sharedKey2 };
}

export async function testEncrypt(publicKey: Buffer) {
  const str = 'message to sign';
  const msg = Buffer.from(str);
  const encrypted = await eccryptoJS.encrypt(publicKey, msg);
  return encrypted;
}
