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
  const msg = Buffer.from(hash);
  const sig = await eccryptoJS.sign(privateKey, msg);
  return { str, msg, sig };
}
