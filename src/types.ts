export interface Encrypted {
  ciphertext: Buffer;
  ephemPublicKey: Buffer;
  iv: Buffer;
  mac: Buffer;
}

export interface PreEncryptOpts extends Encrypted {
  ephemPrivateKey: Buffer;
}

export interface KeyPair {
  privateKey: Buffer;
  publicKey: Buffer;
}

import * as eccryptoJS from './index';

export type IEccrypto = typeof eccryptoJS;

export type OutputModifier = Uint8Array | ((len: number) => Uint8Array);

export interface ISecp256k1 {
  contextRandomize(seed: Uint8Array): void;

  privateKeyVerify(privateKey: Uint8Array): boolean;

  privateKeyNegate(privateKey: Uint8Array): Uint8Array;

  privateKeyTweakAdd(privateKey: Uint8Array, tweak: Uint8Array): Uint8Array;

  privateKeyTweakMul(privateKey: Uint8Array, tweak: Uint8Array): Uint8Array;

  publicKeyVerify(publicKey: Uint8Array): boolean;

  publicKeyCreate(
    privateKey: Uint8Array,
    compressed?: boolean,
    output?: OutputModifier
  ): Uint8Array;

  publicKeyConvert(
    publicKey: Uint8Array,
    compressed?: boolean,
    output?: OutputModifier
  ): Uint8Array;

  publicKeyNegate(
    publicKey: Uint8Array,
    compressed?: boolean,
    output?: OutputModifier
  ): Uint8Array;

  publicKeyCombine(
    publicKeys: Uint8Array[],
    compressed?: boolean,
    output?: OutputModifier
  ): Uint8Array;

  publicKeyTweakAdd(
    publicKey: Uint8Array,
    tweak: Uint8Array,
    compressed?: boolean,
    output?: OutputModifier
  ): Uint8Array;

  publicKeyTweakMul(
    publicKey: Uint8Array,
    tweak: Uint8Array,
    compressed?: boolean,
    output?: OutputModifier
  ): Uint8Array;

  signatureNormalize(signature: Uint8Array): Uint8Array;

  signatureExport(signature: Uint8Array, output?: OutputModifier): Uint8Array;

  signatureImport(signature: Uint8Array, output?: OutputModifier): Uint8Array;

  ecdsaSign(
    message: Uint8Array,
    privateKey: Uint8Array,
    {
      data,
      noncefn,
    }?: {
      data?: Uint8Array;
      noncefn?: (
        message: Uint8Array,
        privateKey: Uint8Array,
        algo: null,
        data: Uint8Array,
        counter: number
      ) => Uint8Array;
    },
    output?: OutputModifier
  ): { signature: Uint8Array; recid: number };

  ecdsaVerify(
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array
  ): boolean;

  ecdsaRecover(
    signature: Uint8Array,
    recid: number,
    message: Uint8Array,
    compressed?: boolean,
    output?: OutputModifier
  ): Uint8Array;

  ecdh(
    publicKey: Uint8Array,
    privateKey: Uint8Array,
    {
      data,
      xbuf,
      ybuf,
      hashfn,
    }?: {
      data?: Uint8Array;
      xbuf?: Uint8Array;
      ybuf?: Uint8Array;
      hashfn?: (x: Uint8Array, y: Uint8Array, data: Uint8Array) => Uint8Array;
    },
    output?: OutputModifier
  ): Uint8Array;
}
