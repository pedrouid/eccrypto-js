import { isHexString } from './validators';
import {
  UTF8_ENC,
  HEX_ENC,
  KEY_LENGTH,
  DECOMPRESSED_LENGTH,
  PREFIXED_KEY_LENGTH,
  PREFIXED_DECOMPRESSED_LENGTH,
} from './constants';

export function removeHexPrefix(hex: string): string {
  return hex.replace(/^0x/, '');
}

export function addHexPrefix(hex: string): string {
  return hex.startsWith('0x') ? hex : `0x${hex}`;
}

export function utf8ToBuffer(utf8: string): Buffer {
  return Buffer.from(utf8, UTF8_ENC);
}

export function hexToBuffer(hex: string): Buffer {
  return Buffer.from(removeHexPrefix(hex), HEX_ENC);
}

export function arrayToBuffer(arr: Uint8Array): Buffer {
  return Buffer.from(arr);
}

export function bufferToUtf8(buf: Buffer): string {
  return buf.toString(UTF8_ENC);
}

export function bufferToHex(buf: Buffer): string {
  return buf.toString(HEX_ENC);
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
  return (
    publicKey.length === KEY_LENGTH || publicKey.length === PREFIXED_KEY_LENGTH
  );
}

export function isDecompressed(publicKey: Buffer): boolean {
  return (
    publicKey.length === DECOMPRESSED_LENGTH ||
    publicKey.length === PREFIXED_DECOMPRESSED_LENGTH
  );
}

export function isPrefixed(publicKey: Buffer) {
  if (isCompressed(publicKey)) {
    return publicKey.length === PREFIXED_KEY_LENGTH;
  }
  return publicKey.length === PREFIXED_DECOMPRESSED_LENGTH;
}

export function sanitizePublicKey(publicKey: Buffer): Buffer {
  return isPrefixed(publicKey)
    ? publicKey
    : Buffer.from(`04${publicKey.toString('hex')}`, 'hex');
}
