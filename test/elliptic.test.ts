import * as eccryptoJS from '../src';
import {
  TEST_PRIVATE_KEY,
  TEST_PUBLIC_KEY,
  TEST_SHARED_KEY,
  compare,
  TEST_PUBLIC_KEY_COMPRESSED,
  getTestMessageToSign,
} from './common';

const privateKey = Buffer.from(TEST_PRIVATE_KEY, 'hex');
const expectedPublicKey = Buffer.from(TEST_PUBLIC_KEY, 'hex');
const expectedPublicKeyLength = 65;
const expectedPublicKeyCompressed = Buffer.from(
  TEST_PUBLIC_KEY_COMPRESSED,
  'hex'
);
const expectedPublicKeyCompressedLength = 33;
const expectedSharedKey = Buffer.from(TEST_SHARED_KEY, 'hex');
const expectedSharedKeyLength = 32;

describe('Elliptic', () => {
  it('should get public key successfully', () => {
    const publicKey = eccryptoJS.ellipticGetPublic(privateKey);
    expect(publicKey).toBeTruthy();
    expect(compare(publicKey, expectedPublicKey)).toBeTruthy();
    expect(publicKey.length === expectedPublicKeyLength).toBeTruthy();
  });

  it('should get public key compressed successfully', () => {
    const publicKeyCompressed = eccryptoJS.ellipticGetPublicCompressed(
      privateKey
    );
    expect(publicKeyCompressed).toBeTruthy();
    expect(
      compare(publicKeyCompressed, expectedPublicKeyCompressed)
    ).toBeTruthy();
    expect(
      publicKeyCompressed.length === expectedPublicKeyCompressedLength
    ).toBeTruthy();
  });

  it('should compress public key successfully', () => {
    const publicKey = eccryptoJS.ellipticGetPublic(privateKey);
    const publicKeyCompressed = eccryptoJS.ellipticCompress(publicKey);
    expect(
      compare(publicKeyCompressed, expectedPublicKeyCompressed)
    ).toBeTruthy();
  });

  it('should decompress public key successfully', () => {
    const publicKeyCompressed = eccryptoJS.ellipticGetPublicCompressed(
      privateKey
    );
    const publicKey = eccryptoJS.ellipticDecompress(publicKeyCompressed);
    expect(compare(publicKey, expectedPublicKey)).toBeTruthy();
  });

  it('should derive shared key successfully', () => {
    const sharedKey = eccryptoJS.ellipticDerive(
      eccryptoJS.ellipticGetPublic(privateKey),
      privateKey
    );
    expect(sharedKey).toBeTruthy();
    expect(compare(sharedKey, expectedSharedKey)).toBeTruthy();
    expect(sharedKey.length === expectedSharedKeyLength).toBeTruthy();
  });

  it('should sign successfully with DER signatures', async () => {
    const { msg } = await getTestMessageToSign();
    const sig = eccryptoJS.ellipticSign(msg, privateKey);
    expect(sig).toBeTruthy();
  });

  it('should verify DER signatures successfully', async () => {
    const { msg } = await getTestMessageToSign();
    const sig = eccryptoJS.ellipticSign(msg, privateKey);
    const publicKey = eccryptoJS.ellipticGetPublic(privateKey);
    await eccryptoJS.ellipticVerify(sig, msg, publicKey);
  });

  it('should sign successfully with RSV signatures', async () => {
    const { msg } = await getTestMessageToSign();
    const sig = eccryptoJS.ellipticSign(msg, privateKey, true);
    expect(sig).toBeTruthy();
  });

  it('should verify RSV signatures successfully', async () => {
    const { msg } = await getTestMessageToSign();
    const sig = eccryptoJS.ellipticSign(msg, privateKey);
    const publicKey = eccryptoJS.ellipticGetPublic(privateKey);
    await eccryptoJS.ellipticVerify(sig, msg, publicKey);
  });
});
