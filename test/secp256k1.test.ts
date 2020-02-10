import * as eccryptoJS from '../src';
import {
  TEST_PRIVATE_KEY,
  TEST_PUBLIC_KEY,
  TEST_SHARED_KEY,
  compare,
} from './common';

const privateKey = Buffer.from(TEST_PRIVATE_KEY, 'hex');
const expectedPublicKey = Buffer.from(TEST_PUBLIC_KEY, 'hex');
const expectedPublicKeyLength = 33;
const expectedSharedKey = Buffer.from(TEST_SHARED_KEY, 'hex');
const expectedSharedKeyLength = 32;

describe('SECP256K1', () => {
  it('should get public key successfully', () => {
    const publicKey = eccryptoJS.secp256k1GetPublic(privateKey);
    expect(publicKey).toBeTruthy();
    expect(compare(publicKey, expectedPublicKey)).toBeTruthy();
    expect(publicKey.length === expectedPublicKeyLength).toBeTruthy();
  });

  it('should derive shared key successfully', () => {
    const sharedKey = eccryptoJS.secp256k1Derive(
      eccryptoJS.secp256k1GetPublic(privateKey),
      privateKey
    );
    expect(sharedKey).toBeTruthy();
    expect(compare(sharedKey, expectedSharedKey)).toBeTruthy();
    expect(sharedKey.length === expectedSharedKeyLength).toBeTruthy();
  });
});

describe('Elliptic', () => {
  it('should get public key successfully', () => {
    const publicKey = eccryptoJS.ellipticGetPublic(privateKey);
    expect(publicKey).toBeTruthy();
    expect(compare(publicKey, expectedPublicKey)).toBeTruthy();
    expect(publicKey.length === expectedPublicKeyLength).toBeTruthy();
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
});
