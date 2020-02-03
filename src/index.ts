import { toUtf8Bytes } from '@ethersproject/strings'
import { arrayify } from '@ethersproject/bytes'
import { randomBytes as _randomBytes } from "@ethersproject/random";
import { sha512 as _sha512, computeHmac, SupportedAlgorithm } from "@ethersproject/sha2"
import { ec as EC } from 'elliptic'
import aesJs from 'aes-js'

type Encrypted = {
  ciphertext: Buffer;
  ephemPublicKey: Buffer;
  iv: Buffer;
  mac: Buffer;
};

var ec = new EC("secp256k1");

const EC_GROUP_ORDER = Buffer.from(
  "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
  "hex"
);
const ZERO32 = Buffer.alloc(32, 0);

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

function isScalar(x: Buffer): boolean {
  return Buffer.isBuffer(x) && x.length === 32;
}

function isValidPrivateKey(privateKey: Buffer): boolean {
  if (!isScalar(privateKey)) {
    return false;
  }
  return (
    privateKey.compare(ZERO32) > 0 && privateKey.compare(EC_GROUP_ORDER) < 0 // > 0
  ); // < G
}

// Compare two buffers in constant time to prevent timing attacks.
function equalConstTime(b1: Buffer, b2: Buffer): boolean {
  if (b1.length !== b2.length) {
    return false;
  }
  var res = 0;
  for (var i = 0; i < b1.length; i++) {
    res |= b1[i] ^ b2[i]; 
  }
  return res === 0;
}

function randomBytes(size: number): Buffer {
  var arr = _randomBytes(size)
  return Buffer.from(arr);
}

function sha512(msg: string): Promise<Uint8Array> {
  return new Promise(async(resolve) => {
    const bytes = toUtf8Bytes(msg)
    var hash = _sha512(bytes)
    resolve(arrayify(hash));
  });
}

function aesCbcEncrypt(iv: Buffer, key: Buffer,data: Buffer): Promise<Buffer> {
  return new Promise((resolve) => {
    var aesCbc = new aesJs.ModeOfOperation.cbc(key, iv);
    var encryptedBytes = aesCbc.encrypt(data);
    resolve(Buffer.from(encryptedBytes));
  })
}

function aesCbcDecrypt(iv: Buffer, key: Buffer,data: Buffer): Promise<Buffer> {
  return new Promise((resolve) => {
    var aesCbc = new aesJs.ModeOfOperation.cbc(key, iv);
    var encryptedBytes = aesCbc.decrypt(data);
    resolve(Buffer.from(encryptedBytes));
  })
}


function hmacSha256Sign(key:Buffer, msg: Buffer): Promise<Buffer> {
  return new Promise(async(resolve) => {
    const result = computeHmac(SupportedAlgorithm.sha256, key, msg)
    resolve(Buffer.from(result));
  });
}

function hmacSha256Verify(key:Buffer, msg:Buffer, sig:Buffer): Promise<boolean> {
  return new Promise(async(resolve) => {
    var expectedSig = await hmacSha256Sign(key, msg)
    resolve(equalConstTime(expectedSig, sig));
  });
}

/**
 * Generate a new valid private key. Will use the window.crypto or window.msCrypto as source
 * depending on your browser.
 * @return {Buffer} A 32-byte private key.
 * @function
 */
export function generatePrivate() {
  var privateKey = randomBytes(32);
  while (!isValidPrivateKey(privateKey)) {
    privateKey = randomBytes(32);
  }
  return privateKey;
};

export function getPublic(privateKey: Buffer) {
  // This function has sync API so we throw an error immediately.
  assert(privateKey.length === 32, "Bad private key");
  assert(isValidPrivateKey(privateKey), "Bad private key");
  // XXX(Kagami): `elliptic.utils.encode` returns array for every
  // encoding except `hex`.
  return Buffer.from(ec.keyFromPrivate(privateKey).getPublic('hex'));
};

/**
 * Get compressed version of public key.
 */
export function getPublicCompressed(privateKey: Buffer) {
  
  assert(privateKey.length === 32, "Bad private key");
  assert(isValidPrivateKey(privateKey), "Bad private key");
  // See https://github.com/wanderer/secp256k1-node/issues/46
  let compressed = true;
  return Buffer.from(
    ec.keyFromPrivate(privateKey).getPublic(compressed, 'hex')
  );
};

export function sign(privateKey:Buffer, msg: Buffer) {
  return new Promise(async(resolve) => {
    assert(privateKey.length === 32, "Bad private key");
    assert(isValidPrivateKey(privateKey), "Bad private key");
    assert(msg.length > 0, "Message should not be empty");
    assert(msg.length <= 32, "Message is too long");
    resolve(Buffer.from(ec.sign(msg, privateKey, { canonical: true }).toDER()));
  });
};

export function verify(publicKey: Buffer, msg: Buffer, sig: Buffer) {
  return new Promise(function(resolve, reject) {
    assert(
      publicKey.length === 65 || publicKey.length === 33,
      "Bad public key"
    );
    if (publicKey.length === 65) {
      assert(publicKey[0] === 4, "Bad public key");
    }
    if (publicKey.length === 33) {
      assert(publicKey[0] === 2 || publicKey[0] === 3, "Bad public key");
    }
    assert(msg.length > 0, "Message should not be empty");
    assert(msg.length <= 32, "Message is too long");
    if (ec.verify(msg, sig, publicKey)) {
      resolve(null);
    } else {
      reject(new Error("Bad signature"));
    }
  });
};

export function derive(privateKeyA: Buffer, publicKeyB: Buffer): Promise<Buffer> {
  return new Promise(async(resolve) => {
    assert(Buffer.isBuffer(privateKeyA), "Bad private key");
    assert(Buffer.isBuffer(publicKeyB), "Bad public key");
    assert(privateKeyA.length === 32, "Bad private key");
    assert(isValidPrivateKey(privateKeyA), "Bad private key");
    assert(
      publicKeyB.length === 65 || publicKeyB.length === 33,
      "Bad public key"
    );
    if (publicKeyB.length === 65) {
      assert(publicKeyB[0] === 4, "Bad public key");
    }
    if (publicKeyB.length === 33) {
      assert(publicKeyB[0] === 2 || publicKeyB[0] === 3, "Bad public key");
    }
    var keyA = ec.keyFromPrivate(privateKeyA);
    var keyB = ec.keyFromPublic(publicKeyB);
    var Px = keyA.derive(keyB.getPublic()); // BN instance
    resolve(Buffer.from(Px.toArray()));
  });
};

export function encrypt(publicKeyTo: Buffer, msg: Buffer, opts: Encrypted) {
  opts = opts || {};
  // Tmp variables to save context from flat promises;
  var iv: Buffer
  var ephemPublicKey: Buffer
  var ciphertext: Buffer
  var macKey: Buffer
  return new Promise(async(resolve) => {
    var ephemPrivateKey = randomBytes(32);
    // There is a very unlikely possibility that it is not a valid key
    ephemPublicKey = getPublic(ephemPrivateKey);
    resolve(derive(ephemPrivateKey, publicKeyTo));
  })
    .then((Px: any) => sha512(Px))
    .then((hash) => {
      iv = opts.iv || randomBytes(16);
      var encryptionKey = hash.slice(0, 32);
      macKey = Buffer.from(hash.slice(32));
      return aesCbcEncrypt(iv, Buffer.from(encryptionKey), msg);
    })
    .then((data) => {
      ciphertext = data;
      var dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
      return hmacSha256Sign(macKey, dataToMac);
    })
    .then((mac) => {
      return {
        iv: iv,
        ephemPublicKey: ephemPublicKey,
        ciphertext: ciphertext,
        mac: mac
      };
    });
};

export function decrypt(privateKey: Buffer, opts: Encrypted) {
  // Tmp variable to save context from flat promises;
  var encryptionKey: Buffer
  return derive(privateKey, opts.ephemPublicKey)
  .then((Px: any) => sha512(Px))
    .then((hash) => {
      encryptionKey = Buffer.from(hash.slice(0, 32));
      var macKey = hash.slice(32);
      var dataToMac = Buffer.concat([
        opts.iv,
        opts.ephemPublicKey,
        opts.ciphertext
      ]);
      return hmacSha256Verify(Buffer.from(macKey), dataToMac, opts.mac);
    })
    .then((macGood) => {
      assert(macGood, "Bad MAC");
      return aesCbcDecrypt(opts.iv, encryptionKey, opts.ciphertext);
    })
    .then((msg) => {
      return Buffer.from(new Uint8Array(msg));
    });
};
