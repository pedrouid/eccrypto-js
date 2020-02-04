import { assert, isValidPrivateKey } from './validators';
import { getCurve } from './ecdsa';

export function derive(
  privateKeyA: Buffer,
  publicKeyB: Buffer
): Promise<Buffer> {
  return new Promise(async resolve => {
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
    const keyA = getCurve().keyFromPrivate(privateKeyA);
    const keyB = getCurve().keyFromPublic(publicKeyB);
    const Px = keyA.derive(keyB.getPublic()); // BN instance
    resolve(Buffer.from(Px.toArray()));
  });
}
