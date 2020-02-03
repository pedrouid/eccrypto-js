# eccrypto-js

## Description

Pure JavaScript Elliptic curve cryptography library

This library is a port from [eccrypto](https://github.com/bitchan/eccrypto) using only pure javascript libraries from [ethers.js](https://github.com/ethers-io/ethers.js) version 5

**NOTE:** This library is still experimental and hasn't been thoroughly tested yet

## Usage

### ECDSA

```js
var crypto = require('crypto');
var eccrypto = require('eccrypto');

// A new random 32-byte private key.
var privateKey = eccrypto.generatePrivate();
// Corresponding uncompressed (65-byte) public key.
var publicKey = eccrypto.getPublic(privateKey);

var str = 'message to sign';
// Always hash you message to sign!
var msg = crypto
  .createHash('sha256')
  .update(str)
  .digest();

eccrypto.sign(privateKey, msg).then(function(sig) {
  console.log('Signature in DER format:', sig);
  eccrypto
    .verify(publicKey, msg, sig)
    .then(function() {
      console.log('Signature is OK');
    })
    .catch(function() {
      console.log('Signature is BAD');
    });
});
```

### ECDH

```js
var eccrypto = require('eccrypto');

var privateKeyA = eccrypto.generatePrivate();
var publicKeyA = eccrypto.getPublic(privateKeyA);
var privateKeyB = eccrypto.generatePrivate();
var publicKeyB = eccrypto.getPublic(privateKeyB);

eccrypto.derive(privateKeyA, publicKeyB).then(function(sharedKey1) {
  eccrypto.derive(privateKeyB, publicKeyA).then(function(sharedKey2) {
    console.log('Both shared keys are equal:', sharedKey1, sharedKey2);
  });
});
```

### ECIES

```js
var eccrypto = require('eccrypto');

var privateKeyA = eccrypto.generatePrivate();
var publicKeyA = eccrypto.getPublic(privateKeyA);
var privateKeyB = eccrypto.generatePrivate();
var publicKeyB = eccrypto.getPublic(privateKeyB);

// Encrypting the message for B.
eccrypto.encrypt(publicKeyB, Buffer.from('msg to b')).then(function(encrypted) {
  // B decrypting the message.
  eccrypto.decrypt(privateKeyB, encrypted).then(function(plaintext) {
    console.log('Message to part B:', plaintext.toString());
  });
});

// Encrypting the message for A.
eccrypto.encrypt(publicKeyA, Buffer.from('msg to a')).then(function(encrypted) {
  // A decrypting the message.
  eccrypto.decrypt(privateKeyA, encrypted).then(function(plaintext) {
    console.log('Message to part A:', plaintext.toString());
  });
});
```

## License

[MIT License](LICENSE.md)
