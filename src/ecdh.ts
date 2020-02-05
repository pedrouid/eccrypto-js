import { assert, isValidPrivateKey } from './validators';
import { keyFromPrivate, keyFromPublic } from './ecdsa';

export async function derive(
  privateKeyA: Buffer,
  publicKeyB: Buffer
): Promise<Buffer> {
  assert(Buffer.isBuffer(privateKeyA), 'Bad private key');
  assert(Buffer.isBuffer(publicKeyB), 'Bad public key');
  assert(privateKeyA.length === 32, 'Bad private key');
  assert(isValidPrivateKey(privateKeyA), 'Bad private key');
  assert(
    publicKeyB.length === 65 || publicKeyB.length === 33,
    'Bad public key'
  );
  if (publicKeyB.length === 65) {
    assert(publicKeyB[0] === 4, 'Bad public key');
  }
  if (publicKeyB.length === 33) {
    assert(publicKeyB[0] === 2 || publicKeyB[0] === 3, 'Bad public key');
  }
  const keyA = keyFromPrivate(privateKeyA);
  const keyB = keyFromPublic(publicKeyB);
  const sharedKey = keyA.derive(keyB.getPublic()); // BN instance
  return Buffer.from(sharedKey.toArray());
}
