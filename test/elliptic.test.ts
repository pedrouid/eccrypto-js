import { ec as EC } from 'elliptic';
import BN from 'bn.js';
import * as eccryptoJS from '../src';
import * as ellipticLib from '../src/lib/elliptic';
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
    const publicKey = ellipticLib.ellipticGetPublic(privateKey);
    expect(publicKey).toBeTruthy();
    expect(compare(publicKey, expectedPublicKey)).toBeTruthy();
    expect(publicKey.length === expectedPublicKeyLength).toBeTruthy();
  });

  it('should get public key compressed successfully', () => {
    const publicKeyCompressed = ellipticLib.ellipticGetPublicCompressed(
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
    const publicKey = ellipticLib.ellipticGetPublic(privateKey);
    const publicKeyCompressed = ellipticLib.ellipticCompress(publicKey);
    expect(
      compare(publicKeyCompressed, expectedPublicKeyCompressed)
    ).toBeTruthy();
  });

  it('should decompress public key successfully', () => {
    const publicKeyCompressed = ellipticLib.ellipticGetPublicCompressed(
      privateKey
    );
    const publicKey = ellipticLib.ellipticDecompress(publicKeyCompressed);
    expect(compare(publicKey, expectedPublicKey)).toBeTruthy();
  });

  it('should derive shared key successfully', () => {
    const sharedKey = ellipticLib.ellipticDerive(
      ellipticLib.ellipticGetPublic(privateKey),
      privateKey
    );
    expect(sharedKey).toBeTruthy();
    expect(compare(sharedKey, expectedSharedKey)).toBeTruthy();
    expect(sharedKey.length === expectedSharedKeyLength).toBeTruthy();
  });

  it('should sign successfully with DER signatures', async () => {
    const { msg } = await getTestMessageToSign();
    const sig = ellipticLib.ellipticSign(msg, privateKey);
    expect(sig).toBeTruthy();
  });

  it('should verify DER signatures successfully', async () => {
    const { msg } = await getTestMessageToSign();
    const sig = ellipticLib.ellipticSign(msg, privateKey);
    const publicKey = ellipticLib.ellipticGetPublic(privateKey);
    await ellipticLib.ellipticVerify(sig, msg, publicKey);
  });

  it('should throw when recovering from DER signatures', async () => {
    const { msg } = await getTestMessageToSign();
    const sig = ellipticLib.ellipticSign(msg, privateKey);
    // const publicKey = ellipticLib.ellipticGetPublic(privateKey);
    expect(() => ellipticLib.ellipticRecover(sig, msg)).toThrow(
      'Cannot recover from DER signatures'
    );
  });

  it('should sign successfully with RSV signatures', async () => {
    const { msg } = await getTestMessageToSign();
    const sig = ellipticLib.ellipticSign(msg, privateKey, true);
    expect(sig).toBeTruthy();
  });

  it('should verify RSV signatures successfully', async () => {
    const { msg } = await getTestMessageToSign();
    const sig = ellipticLib.ellipticSign(msg, privateKey);
    const publicKey = ellipticLib.ellipticGetPublic(privateKey);
    await ellipticLib.ellipticVerify(sig, msg, publicKey);
  });

  it('should recover RSV signatures successfully', async () => {
    const { msg } = await getTestMessageToSign();
    const sig = ellipticLib.ellipticSign(msg, privateKey, true);
    const publicKey = ellipticLib.ellipticGetPublic(privateKey);
    const recovered = ellipticLib.ellipticRecover(sig, msg);
    expect(compare(publicKey, recovered)).toBeTruthy();
  });

  it('should sanitize RSV signatures correctly', async () => {
    // this test ensures that browser RSV signatures are padded correctly to 64 bytes for each scalar
    const signature: EC.Signature = {
      r: new BN(
        '73a234f798e877c7cf3aebefc4c200fff728c147e9c5bacffaac451fdea4f553',
        'hex'
      ),
      s: new BN(
        '79992a90274bb8d7690684f4406f28684fa19ac1fff68a97fc356aef8911a8',
        'hex'
      ),
      recoveryParam: 1,
      toDER: (enc?: string | null): any => {},
    };
    const result = ellipticLib.ellipticRSVSignature(signature);
    const expected =
      '73a234f798e877c7cf3aebefc4c200fff728c147e9c5bacffaac451fdea4f5530079992a90274bb8d7690684f4406f28684fa19ac1fff68a97fc356aef8911a81c';
    expect(eccryptoJS.bufferToHex(result)).toEqual(expected);
  });
});
