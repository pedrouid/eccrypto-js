import * as eccrypto from 'eccrypto';
import * as eccryptoJS from '../src';
import {
  compare,
  testGenerateKeyPair,
  testSign,
  testEncrypt,
  testRandomBytes,
  testEcies,
} from './common';

describe('eccrypto', () => {
  let keyPair: eccryptoJS.KeyPair;

  beforeEach(() => {
    keyPair = testGenerateKeyPair();
  });

  it('should be able to sign with eccrypto-js keys', async () => {
    const { sig: sig2 } = await testSign(
      keyPair.privateKey,
      false,
      eccrypto as any
    );
    expect(sig2).toBeTruthy();
  });

  it('should be able to verify signature from eccrypto-js', async () => {
    const { sig: sig2, msg: msg2 } = await testSign(
      keyPair.privateKey,
      false,
      eccrypto as any
    );
    eccryptoJS.verify(keyPair.publicKey, msg2, sig2);
  });

  it('should be able to verify with eccrypto-js signature', async () => {
    const { sig: sig2, msg: msg2 } = await testSign(keyPair.privateKey, false);
    // @ts-ignore
    await eccrypto.verify(keyPair.publicKey, msg2, sig2);
  });

  it('should match public keys from eccrypto-js', async () => {
    const publicKey1 = eccryptoJS.getPublic(keyPair.privateKey);
    const publicKey2 = eccrypto.getPublic(keyPair.privateKey);

    const isMatch = compare(publicKey1, publicKey2);
    expect(isMatch).toBeTruthy();
  });

  it('should match compressed public keys from eccrypto-js', async () => {
    const publicKeyCompressed1 = eccryptoJS.getPublicCompressed(
      keyPair.privateKey
    );
    const publicKeyCompressed2 = eccrypto.getPublicCompressed(
      keyPair.privateKey
    );

    const isMatch = compare(publicKeyCompressed1, publicKeyCompressed2);
    expect(isMatch).toBeTruthy();
  });

  it('should match derived sharedKeys from eccrypto-js', async () => {
    const keyPairA = testGenerateKeyPair();
    const keyPairB = testGenerateKeyPair();

    const sharedKey1 = eccryptoJS.derive(
      keyPairA.privateKey,
      keyPairB.publicKey
    );
    const sharedKey2 = await eccrypto.derive(
      keyPairA.privateKey,
      keyPairB.publicKey
    );

    const isMatch1 = compare(sharedKey1, sharedKey2);
    expect(isMatch1).toBeTruthy();

    const sharedKey3 = eccryptoJS.derive(
      keyPairB.privateKey,
      keyPairA.publicKey
    );
    const sharedKey4 = await eccrypto.derive(
      keyPairB.privateKey,
      keyPairA.publicKey
    );

    const isMatch2 = compare(sharedKey3, sharedKey4);
    expect(isMatch2).toBeTruthy();
  });

  it('should be decryptable by eccrypto-js and match inputs', async () => {
    const opts = { ephemPrivateKey: testGenerateKeyPair().privateKey };
    const { str: str2, encrypted: encrypted2 } = await testEncrypt(
      keyPair.publicKey,
      opts,
      eccrypto as any
    );

    const decrypted1 = await eccryptoJS.decrypt(keyPair.privateKey, encrypted2);
    expect(decrypted1).toBeTruthy();

    const isMatch = decrypted1.toString() === str2;
    expect(isMatch).toBeTruthy();
  });

  it('should decrypt and match input from eccrypto-js', async () => {
    const opts = { ephemPrivateKey: testGenerateKeyPair().privateKey };
    const { str: str1, encrypted: encrypted1 } = await testEncrypt(
      keyPair.publicKey,
      opts
    );

    const decrypted2 = await eccrypto.decrypt(keyPair.privateKey, encrypted1);
    expect(decrypted2).toBeTruthy();

    const isMatch = decrypted2.toString() === str1;
    expect(isMatch).toBeTruthy();
  });

  it('should match all encryption keys from eccrypto-js', async () => {
    const keyPair = testGenerateKeyPair();
    const opts = {
      ephemPrivateKey: testGenerateKeyPair().privateKey,
      iv: testRandomBytes(16),
    };

    const {
      str: str1,
      msg: msg1,
      ephemPrivateKey: ephemPrivateKey1,
      ephemPublicKey: ephemPublicKey1,
      sharedKey: sharedKey1,
      hash: hash1,
      encryptionKey: encryptionKey1,
      macKey: macKey1,
      iv: iv1,
      ciphertext: ciphertext1,
      dataToMac: dataToMac1,
      mac: mac1,
    } = await testEcies(keyPair.publicKey, opts);
    const {
      str: str2,
      msg: msg2,
      ephemPrivateKey: ephemPrivateKey2,
      ephemPublicKey: ephemPublicKey2,
      sharedKey: sharedKey2,
      hash: hash2,
      encryptionKey: encryptionKey2,
      macKey: macKey2,
      iv: iv2,
      ciphertext: ciphertext2,
      dataToMac: dataToMac2,
      mac: mac2,
    } = await testEcies(keyPair.publicKey, opts, eccrypto as any);
    expect(str1 === str2).toBeTruthy();
    expect(compare(msg1, msg2)).toBeTruthy();
    expect(compare(ephemPrivateKey1, ephemPrivateKey2)).toBeTruthy();
    expect(compare(ephemPublicKey1, ephemPublicKey2)).toBeTruthy();
    expect(compare(sharedKey1, sharedKey2)).toBeTruthy();
    expect(compare(hash1, hash2)).toBeTruthy();
    expect(compare(encryptionKey1, encryptionKey2)).toBeTruthy();
    expect(compare(macKey1, macKey2)).toBeTruthy();
    expect(compare(iv1, iv2)).toBeTruthy();
    expect(compare(ciphertext1, ciphertext2)).toBeTruthy();
    expect(compare(dataToMac1, dataToMac2)).toBeTruthy();
    expect(compare(mac1, mac2)).toBeTruthy();
  });
});
