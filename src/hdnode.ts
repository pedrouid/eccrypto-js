import HDKey from 'hdKey';
import { entropyToMnemonic } from './lib/bip39';
import { randomBytes } from './random';
import { KEY_LENGTH } from './helpers/constants';

export class HDNode {
  public static createRandom(): HDNode {
    return new HDNode(
      HDKey.fromMasterSeed(entropyToMnemonic(randomBytes(KEY_LENGTH)))
    );
  }

  public static fromMasterSeed(seedPhrase: Buffer): HDNode {
    return new HDNode(HDKey.fromMasterSeed(seedPhrase));
  }

  public static fromExtendedKey(base58Key: string): HDNode {
    return new HDNode(HDKey.fromExtendedKey(base58Key));
  }

  constructor(private readonly hdKey?: any) {}

  public privateExtendedKey(): Buffer {
    if (!this.hdKey.privateExtendedKey) {
      throw new Error('This is a public key only wallet');
    }
    return this.hdKey.privateExtendedKey;
  }

  public publicExtendedKey(): Buffer {
    return this.hdKey.publicExtendedKey;
  }

  public derivePath(path: string): HDNode {
    return new HDNode(this.hdKey.derive(path));
  }

  public deriveChild(index: number): HDNode {
    return new HDNode(this.hdKey.deriveChild(index));
  }
}
