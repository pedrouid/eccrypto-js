# eccrypto-js [![npm version](https://badge.fury.io/js/eccrypto-js.svg)](https://badge.fury.io/js/eccrypto-js)

Pure JavaScript Elliptic curve cryptography library

## Description

This library is a port from [eccrypto](https://github.com/bitchan/eccrypto) using only pure javascript libraries from [ethers.js](https://github.com/ethers-io/ethers.js) version 5

**NOTE:** This library is still experimental and hasn't been thoroughly tested yet

## Usage

### ECDSA

```typescript
import * as eccryptoJS from 'eccrypto-js';

const keyPair = eccryptoJS.generateKeyPair();

const str = 'message to sign';

const msg = eccryptoJS.sha256(str);

const sig = await eccryptoJS.sign(keyPair.privateKey, msg);

await eccryptoJS.verify(keyPair.publicKey, msg, sig);

// verify will throw if signature is BAD
```

### ECDH

```typescript
import * as eccryptoJS from 'eccrypto-js';

const keyPairA = eccryptoJS.generateKeyPair();
const keyPairB = eccryptoJS.generateKeyPair();

const sharedKey1 = await eccryptoJS.derive(
  keyPairA.privateKey,
  keyPairB.publicKey
);

const sharedKey2 = await eccryptoJS.derive(
  keyPairB.privateKey,
  keyPairA.publicKey
);

// sharedKey1 === sharedKey2
```

### ECIES

```typescript
import * as eccryptoJS from 'eccrypto-js';

const keyPair = eccryptoJS.generateKeyPair();

const str = 'message to sign';

const msg = Buffer.from(str);

const encrypted = await eccryptoJS.encrypt(keyPairB.publicKey, msg);

const decrypted = await eccryptoJS.decrypt(keyPairB.privateKey, encrypted);

// decrypted === msg
```

## License

[MIT License](LICENSE.md)
