export type Encrypted = {
  ciphertext: Buffer;
  ephemPublicKey: Buffer;
  iv: Buffer;
  mac: Buffer;
};

export type KeyPair = {
  privateKey: Buffer;
  publicKey: Buffer;
};
