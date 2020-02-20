import HDKey from './lib/hdkey';
import { entropyToMnemonic } from './lib/bip39';
import { randomBytes } from './random';
import { KEY_LENGTH } from './helpers/constants';

export class HDNode {
  public static async createRandom(): Promise<HDNode> {
    const entropy = await entropyToMnemonic(randomBytes(KEY_LENGTH));
    return new HDNode(HDKey.fromMasterSeed(entropy));
  }

  public static async fromMasterSeed(seedPhrase: Buffer): Promise<HDNode> {
    return new HDNode(HDKey.fromMasterSeed(seedPhrase));
  }

  public static async fromExtendedKey(base58Key: string): Promise<HDNode> {
    return new HDNode(HDKey.fromExtendedKey(base58Key));
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
