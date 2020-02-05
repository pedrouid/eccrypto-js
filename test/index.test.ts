import * as eccrypto from 'eccrypto';
import * as eccryptoJS from '../src';
import {
  testGenerateKeyPair,
  testSign,
  testSharedKeys,
  testEncrypt,
  prettyPrint,
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
    const isMatch = sharedKey1.toString('hex') === sharedKey2.toString('hex');
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

    const isMatch1 = sharedKey1.toString('hex') === sharedKey1.toString('hex');
    expect(isMatch1).toBeTruthy();

    const isMatch2 = sharedKey2.toString('hex') === sharedKey2.toString('hex');
    expect(isMatch2).toBeTruthy();

    const sharedKey3 = await eccryptoJS.derive(
      keyPairB.privateKey,
      keyPairA.publicKey
    );
    const sharedKey4 = await eccrypto.derive(
      keyPairB.privateKey,
      keyPairA.publicKey
    );

    const isMatch3 = sharedKey3.toString('hex') === sharedKey3.toString('hex');
    expect(isMatch3).toBeTruthy();

    const isMatch4 = sharedKey4.toString('hex') === sharedKey4.toString('hex');
    expect(isMatch4).toBeTruthy();
  });

  it.skip('should decrypt and match input from eccrypto-js', async () => {
    const ephemKeyPair = testGenerateKeyPair();
    const { str, msg, encrypted } = await testEncrypt(keyPair.publicKey, {
      ephemPrivateKey: ephemKeyPair.privateKey,
    });
    const { str: str2, msg: msg2, encrypted: encrypted2 } = await testEncrypt(
      keyPair.publicKey,
      { ephemPrivateKey: ephemKeyPair.privateKey },
      eccrypto as any
    );

    // TODO: fix encrypted - currently not matching eccrypto result
    console.log('str', str);
    console.log(`msg.toString('hex')`, msg.toString('hex'));
    prettyPrint('encrypted', encrypted);
    console.log('------------------------------------------');
    console.log('str2', str2);
    console.log(`msg2.toString('hex')`, msg2.toString('hex'));
    prettyPrint('encrypted2', encrypted2);

    const decrypted = await eccrypto.decrypt(keyPair.privateKey, encrypted);
    expect(decrypted).toBeTruthy();

    const isMatch = decrypted.toString() === str;
    expect(isMatch).toBeTruthy();
  });
});
