import { isHexString } from './validators';

export function removeHexPrefix(hex: string): string {
  return hex.replace(/^0x/, '');
}

export function addHexPrefix(hex: string): string {
  return hex.startsWith('0x') ? hex : `0x${hex}`;
}

export function utf8ToBuffer(utf8: string): Buffer {
  return Buffer.from(utf8, 'utf8');
}

export function hexToBuffer(hex: string): Buffer {
  return Buffer.from(removeHexPrefix(hex), 'hex');
}

export function arrayToBuffer(arr: Uint8Array): Buffer {
  return Buffer.from(arr);
}

export function bufferToUtf8(buf: Buffer): string {
  return buf.toString('utf8');
}

export function bufferToHex(buf: Buffer): string {
  return addHexPrefix(buf.toString('hex'));
}

export function bufferToArray(buf: Buffer): Uint8Array {
  return new Uint8Array(buf);
}

export function ensureLength(data: Buffer, expectedLength: number) {
  const diff = data.length - expectedLength;
  if (diff > 0) {
    data = data.slice(diff);
  }
  return data;
}

export function prepareHash(msg: Buffer | string) {
  const buf = Buffer.isBuffer(msg)
    ? msg
    : isHexString(msg)
    ? hexToBuffer(msg)
    : utf8ToBuffer(msg);
  return buf;
}

export function isCompressed(publicKey: Buffer): boolean {
  return publicKey.length === 32 || publicKey.length === 33;
}

export function isDecompressed(publicKey: Buffer): boolean {
  return publicKey.length === 64 || publicKey.length === 65;
}

export function isPrefixed(publicKey: Buffer) {
  if (isCompressed(publicKey)) {
    return publicKey.length === 33;
  }
  return publicKey.length === 65;
}

export function sanitizePublicKey(publicKey: Buffer): Buffer {
  return isPrefixed(publicKey)
    ? publicKey
    : Buffer.from(`04${publicKey.toString('hex')}`, 'hex');
}
