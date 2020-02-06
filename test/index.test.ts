import * as eccrypto from 'eccrypto';
import * as eccryptoJS from '../src';
import {
  compare,
  testGenerateKeyPair,
  testSign,
  testSharedKeys,
  testEncrypt,
  testRandomBytes,
  testEncryptedStepByStep,
} from './common';

describe('ECDSA', () => {
  let keyPair: eccryptoJS.KeyPair;

  beforeEach(() => {
    keyPair = testGenerateKeyPair();
  });

  it('should generate KeyPair', () => {
    expect(keyPair).toBeTruthy();
  });

  it('should sign successfully', async () => {
    const { sig } = await testSign(keyPair.privateKey);
    expect(sig).toBeTruthy();
  });

  it('should verify signature', async () => {
    const { sig, msg } = await testSign(keyPair.privateKey);
    await eccryptoJS.verify(keyPair.publicKey, msg, sig);
  });
});

describe('ECDH', () => {
  let sharedKey1: Buffer;
  let sharedKey2: Buffer;

  beforeEach(async () => {
    const sharedKeys = await testSharedKeys();
    sharedKey1 = sharedKeys.sharedKey1;
    sharedKey2 = sharedKeys.sharedKey2;
  });

  it('should derive shared keys succesfully', () => {
    expect(sharedKey1).toBeTruthy();
    expect(sharedKey2).toBeTruthy();
  });

  it('derived shared keys should match', () => {
    const isMatch = compare(sharedKey1, sharedKey2);
    expect(isMatch).toBeTruthy();
  });
});

describe('ECIES', () => {
  let keyPair: eccryptoJS.KeyPair;

  beforeEach(() => {
    keyPair = testGenerateKeyPair();
  });

  it('should encrypt successfully', async () => {
    const { encrypted } = await testEncrypt(keyPair.publicKey);
    expect(encrypted).toBeTruthy();
  });

  it('should decrypt successfully', async () => {
    const { encrypted } = await testEncrypt(keyPair.publicKey);

    const decrypted = await eccryptoJS.decrypt(keyPair.privateKey, encrypted);
    expect(decrypted).toBeTruthy();
  });

  it('decrypted result should match input', async () => {
    const { str, encrypted } = await testEncrypt(keyPair.publicKey);

    const decrypted = await eccryptoJS.decrypt(keyPair.privateKey, encrypted);
    expect(decrypted).toBeTruthy();

    const isMatch = decrypted.toString() === str;
    expect(isMatch).toBeTruthy();
  });
});

describe('eccrypto', () => {
  let keyPair: eccryptoJS.KeyPair;

  beforeEach(() => {
    keyPair = testGenerateKeyPair();
  });

  it('should be able to sign with eccrypto-js keys', async () => {
    const { sig } = await testSign(keyPair.privateKey, eccrypto as any);
    expect(sig).toBeTruthy();
  });

  it('should be able to verify with eccrypto-js signature', async () => {
    const { sig, msg } = await testSign(keyPair.privateKey);
    // @ts-ignore
    await eccrypto.verify(keyPair.publicKey, msg, sig);
  });

  it('should match derived sharedKeys from eccrypto-js', async () => {
    const keyPairA = testGenerateKeyPair();
    const keyPairB = testGenerateKeyPair();

    const sharedKey1 = await eccryptoJS.derive(
      keyPairA.privateKey,
      keyPairB.publicKey
    );
    const sharedKey2 = await eccrypto.derive(
      keyPairA.privateKey,
      keyPairB.publicKey
    );

    const isMatch1 = compare(sharedKey1, sharedKey1);
    expect(isMatch1).toBeTruthy();

    const isMatch2 = compare(sharedKey2, sharedKey2);
    expect(isMatch2).toBeTruthy();

    const sharedKey3 = await eccryptoJS.derive(
      keyPairB.privateKey,
      keyPairA.publicKey
    );
    const sharedKey4 = await eccrypto.derive(
      keyPairB.privateKey,
      keyPairA.publicKey
    );

    const isMatch3 = compare(sharedKey3, sharedKey3);
    expect(isMatch3).toBeTruthy();

    const isMatch4 = compare(sharedKey4, sharedKey4);
    expect(isMatch4).toBeTruthy();
  });

  it('should decrypt and match input from eccrypto-js', async () => {
    const opts = { ephemPrivateKey: testGenerateKeyPair().privateKey };
    const { str, encrypted: encrypted1 } = await testEncrypt(
      keyPair.publicKey,
      opts
    );

    const decrypted = await eccrypto.decrypt(keyPair.privateKey, encrypted1);
    expect(decrypted).toBeTruthy();

    const isMatch = decrypted.toString() === str;
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
    } = await testEncryptedStepByStep(keyPair.publicKey, opts);
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
    } = await testEncryptedStepByStep(keyPair.publicKey, opts, eccrypto as any);
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
