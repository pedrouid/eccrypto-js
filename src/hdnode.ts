import HDKey from './lib/hdkey';
import { entropyToMnemonic } from './lib/bip39';
import { randomBytes } from './random';
import { KEY_LENGTH } from './helpers/constants';

export class HDNode {
  public static createRandom(): HDNode {
    const entropy = entropyToMnemonic(randomBytes(KEY_LENGTH));
    return new HDNode(new HDKey().fromMasterSeed(entropy));
  }

  public static fromMasterSeed(seedPhrase: Buffer): HDNode {
    return new HDNode(new HDKey().fromMasterSeed(seedPhrase));
  }

  public static fromExtendedKey(base58Key: string): HDNode {
    return new HDNode(new HDKey().fromExtendedKey(base58Key));
  }

  constructor(private readonly hdKey?: HDKey) {}

  get xpub() {
    return this.publicExtendedKey();
  }

  get xpriv() {
    return this.privateExtendedKey();
  }

  public privateExtendedKey(): Buffer {
    if (!this.hdKey?.privateExtendedKey) {
      throw new Error('This is a public key only wallet');
    }
    return this.hdKey?.privateExtendedKey;
  }

  public publicExtendedKey(): Buffer {
    return this.hdKey?.publicExtendedKey;
  }

  public derivePath(path: string): HDNode {
    return new HDNode(this.hdKey?.derive(path));
  }

  public deriveChild(index: number): HDNode {
    return new HDNode(this.hdKey?.deriveChild(index));
  }
}
