import assert from 'assert';
import bs58check from 'bs58check';
import secp256k1 from 'secp256k1';
import { randomBytes } from '../../random';
import { isNode, nodeRipemd160, nodeSha256, nodeHmacSha512Sign } from '../node';
import {
  fallbackRipemd160,
  fallbackSha256,
  fallbackHmacSha512Sign,
} from '../fallback';

const MASTER_SECRET = Buffer.from('Bitcoin seed', 'utf8');
const HARDENED_OFFSET = 0x80000000;
const LEN = 78;

// Bitcoin hardcoded by default, can use package `coininfo` for others
const BITCOIN_VERSIONS = { private: 0x0488ade4, public: 0x0488b21e };

function hash160(buf) {
  if (isNode()) {
    return nodeRipemd160(nodeSha256(buf));
  }
  return fallbackRipemd160(fallbackSha256(buf));
}

function createHmac512Sync(key, data) {
  if (isNode()) {
    return nodeHmacSha512Sign(key, data);
  }
  return fallbackHmacSha512Sign(key, data);
}

class HDKey {
  public versions: any;

  public depth = 0;
  public index = 0;

  public _privateKey: any = null;
  public _publicKey: any = null;
  public chainCode: any = null;
  public _identifier: any = null;

  public _fingerprint = 0;
  public parentFingerprint = 0;

  public MASTER_SECRET = MASTER_SECRET;
  public HARDENED_OFFSET = HARDENED_OFFSET;
  public LEN = LEN;

  constructor(versions: any = BITCOIN_VERSIONS) {
    this.versions = versions;
  }

  get fingerprint() {
    return this._fingerprint;
  }
  get identifier() {
    return this._identifier;
  }
  get pubKeyHash() {
    return this.identifier;
  }

  get privateKey() {
    return this._privateKey;
  }

  set privateKey(value: any) {
    assert.equal(value.length, 32, 'Private key must be 32 bytes.');
    assert(secp256k1.privateKeyVerify(value) === true, 'Invalid private key');

    this._privateKey = value;
    this._publicKey = secp256k1.publicKeyCreate(value, true);
    this._identifier = hash160(this.publicKey);
    this._fingerprint = this._identifier.slice(0, 4).readUInt32BE(0);
  }

  get publicKey() {
    return this._publicKey;
  }

  set publicKey(value: any) {
    assert(
      value.length === 33 || value.length === 65,
      'Public key must be 33 or 65 bytes.'
    );
    assert(secp256k1.publicKeyVerify(value) === true, 'Invalid public key');

    this._publicKey = secp256k1.publicKeyConvert(value, true); // force compressed point
    this._identifier = hash160(this.publicKey);
    this._fingerprint = this._identifier.slice(0, 4).readUInt32BE(0);
    this._privateKey = null;
  }

  get privateExtendedKey() {
    if (this._privateKey)
      return bs58check.encode(
        this.serialize(
          this,
          this.versions.private,
          Buffer.concat([Buffer.alloc(1, 0), this.privateKey])
        )
      );
    else return null;
  }

  get publicExtendedKey() {
    return bs58check.encode(
      this.serialize(this, this.versions.public, this.publicKey)
    );
  }

  public sign(hash) {
    return secp256k1.sign(hash, this.privateKey).signature;
  }

  public verify(hash, signature) {
    return secp256k1.verify(hash, signature, this.publicKey);
  }

  public derive(path: string, isHardened?: boolean) {
    if (path === 'm' || path === 'M' || path === "m'" || path === "M'") {
      return this;
    }

    let entries = path.split('/');
    let hdkey = this;
    entries.forEach(function(c, i) {
      if (i === 0) {
        assert(/^[mM]{1}/.test(c), 'Path must start with "m" or "M"');
        return;
      }

      let hardened = isHardened || (c.length > 1 && c[c.length - 1] === "'");
      let childIndex = parseInt(c, 10); // & (HARDENED_OFFSET - 1)
      assert(childIndex < HARDENED_OFFSET, 'Invalid index');
      if (hardened) childIndex += HARDENED_OFFSET;

      hdkey = (hdkey as any).deriveChild(childIndex);
    });

    return hdkey;
  }

  public deriveChild(index) {
    let isHardened = index >= HARDENED_OFFSET;
    let indexBuffer = Buffer.allocUnsafe(4);
    indexBuffer.writeUInt32BE(index, 0);

    let data;

    if (isHardened) {
      // Hardened child
      assert(this.privateKey, 'Could not derive hardened child key');

      let pk = this.privateKey;
      let zb = Buffer.alloc(1, 0);
      pk = Buffer.concat([zb, pk]);

      // data = 0x00 || ser256(kpar) || ser32(index)
      data = Buffer.concat([pk, indexBuffer]);
    } else {
      // Normal child
      // data = serP(point(kpar)) || ser32(index)
      //      = serP(Kpar) || ser32(index)
      data = Buffer.concat([this.publicKey, indexBuffer]);
    }

    let I = createHmac512Sync(this.chainCode, data);
    let IL = I.slice(0, 32);
    let IR = I.slice(32);

    let hdkey = new HDKey(this.versions);

    // Private parent key -> private child key
    if (this.privateKey) {
      // ki = parse256(IL) + kpar (mod n)
      try {
        hdkey.privateKey = secp256k1.privateKeyTweakAdd(this.privateKey, IL);
        // throw if IL >= n || (privateKey + IL) === 0
      } catch (err) {
        // In case parse256(IL) >= n or ki == 0, one should proceed with the next value for i
        return this.derive(index + 1);
      }
      // Public parent key -> public child key
    } else {
      // Ki = point(parse256(IL)) + Kpar
      //    = G*IL + Kpar
      try {
        hdkey.publicKey = secp256k1.publicKeyTweakAdd(this.publicKey, IL, true);
        // throw if IL >= n || (g**IL + publicKey) is infinity
      } catch (err) {
        // In case parse256(IL) >= n or Ki is the point at infinity, one should proceed with the next value for i
        return this.derive(index + 1, isHardened);
      }
    }

    hdkey.chainCode = IR;
    hdkey.depth = this.depth + 1;
    hdkey.parentFingerprint = this.fingerprint; // .readUInt32BE(0)
    hdkey.index = index;

    return hdkey;
  }

  public fromMasterSeed(seedBuffer, versions?: any) {
    let I = createHmac512Sync(MASTER_SECRET, seedBuffer);
    let IL = I.slice(0, 32);
    let IR = I.slice(32);

    let hdkey = new HDKey(versions);
    hdkey.chainCode = IR;
    hdkey.privateKey = IL;

    return hdkey;
  }

  public fromExtendedKey(base58key, versions?: any) {
    // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
    versions = versions || BITCOIN_VERSIONS;
    let hdkey = new HDKey(versions);

    let keyBuffer = bs58check.decode(base58key);

    let version = keyBuffer.readUInt32BE(0);
    assert(
      version === versions.private || version === versions.public,
      'Version mismatch: does not match private or public'
    );

    hdkey.depth = keyBuffer.readUInt8(4);
    hdkey.parentFingerprint = keyBuffer.readUInt32BE(5);
    hdkey.index = keyBuffer.readUInt32BE(9);
    hdkey.chainCode = keyBuffer.slice(13, 45);

    let key = keyBuffer.slice(45);
    if (key.readUInt8(0) === 0) {
      // private
      assert(
        version === versions.private,
        'Version mismatch: version does not match private'
      );
      hdkey.privateKey = key.slice(1); // cut off first 0x0 byte
    } else {
      assert(
        version === versions.public,
        'Version mismatch: version does not match public'
      );
      hdkey.publicKey = key;
    }

    return hdkey;
  }

  public wipePrivateData() {
    if (this._privateKey)
      randomBytes(this._privateKey.length).copy(this._privateKey);
    this._privateKey = null;
    return this;
  }

  public toJSON() {
    return {
      xpriv: this.privateExtendedKey,
      xpub: this.publicExtendedKey,
    };
  }

  public fromJSON(obj) {
    return this.fromExtendedKey(obj.xpriv);
  }

  public serialize(hdkey, version, key) {
    // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
    let buffer = Buffer.allocUnsafe(LEN);

    buffer.writeUInt32BE(version, 0);
    buffer.writeUInt8(hdkey.depth, 4);

    let fingerprint = hdkey.depth ? hdkey.parentFingerprint : 0x00000000;
    buffer.writeUInt32BE(fingerprint, 5);
    buffer.writeUInt32BE(hdkey.index, 9);

    hdkey.chainCode.copy(buffer, 13);
    key.copy(buffer, 45);

    return buffer;
  }
}

export default HDKey;
