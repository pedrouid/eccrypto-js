import {
  INVALID_MNEMONIC,
  DEFAULT_WORDLIST,
  INVALID_ENTROPY,
  INVALID_CHECKSUM,
  WORDLIST_REQUIRED,
} from './constants';

import {
  normalize,
  lpad,
  binaryToByte,
  bytesToBinary,
  deriveChecksumBits,
} from './utils';

export function entropyToMnemonic(
  entropy: Buffer,
  wordlist?: string[]
): string {
  if (!Buffer.isBuffer(entropy)) entropy = Buffer.from(entropy, 'hex');
  wordlist = wordlist || DEFAULT_WORDLIST;
  if (!wordlist) {
    throw new Error(WORDLIST_REQUIRED);
  }

  // 128 <= ENT <= 256
  if (entropy.length < 16) throw new TypeError(INVALID_ENTROPY);
  if (entropy.length > 32) throw new TypeError(INVALID_ENTROPY);
  if (entropy.length % 4 !== 0) throw new TypeError(INVALID_ENTROPY);

  const entropyBits = bytesToBinary(Array.from(entropy));
  const checksumBits = deriveChecksumBits(entropy);

  const bits = entropyBits + checksumBits;
  const chunks = bits.match(/(.{1,11})/g)!;
  const words = chunks.map(binary => {
    const index = binaryToByte(binary);
    return wordlist![index];
  });

  return wordlist[0] === '\u3042\u3044\u3053\u304f\u3057\u3093' // Japanese wordlist
    ? words.join('\u3000')
    : words.join(' ');
}

export function mnemonicToEntropy(
  mnemonic: string,
  wordlist?: string[]
): string {
  wordlist = wordlist || DEFAULT_WORDLIST;
  if (!wordlist) {
    throw new Error(WORDLIST_REQUIRED);
  }

  const words = normalize(mnemonic).split(' ');
  if (words.length % 3 !== 0) throw new Error(INVALID_MNEMONIC);

  // convert word indices to 11 bit binary strings
  const bits = words
    .map(word => {
      const index = wordlist!.indexOf(word);
      if (index === -1) throw new Error(INVALID_MNEMONIC);

      return lpad(index.toString(2), '0', 11);
    })
    .join('');

  // split the binary string into ENT/CS
  const dividerIndex = Math.floor(bits.length / 33) * 32;
  const entropyBits = bits.slice(0, dividerIndex);
  const checksumBits = bits.slice(dividerIndex);

  // calculate the checksum and compare
  const entropyBytes = entropyBits.match(/(.{1,8})/g)!.map(binaryToByte);
  if (entropyBytes.length < 16) throw new Error(INVALID_ENTROPY);
  if (entropyBytes.length > 32) throw new Error(INVALID_ENTROPY);
  if (entropyBytes.length % 4 !== 0) throw new Error(INVALID_ENTROPY);

  const entropy = Buffer.from(entropyBytes);
  const newChecksum = deriveChecksumBits(entropy);
  if (newChecksum !== checksumBits) throw new Error(INVALID_CHECKSUM);

  return entropy.toString('hex');
}
