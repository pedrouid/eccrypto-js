import aesJs from 'aes-js';
import { isHexString } from '@ethersproject/bytes';

export function removeHexPrefix(hex: string): string {
  return hex.replace(/^0x/, '');
}

export function addHexPrefix(hex: string): string {
  return hex.startsWith('0x') ? hex : `0x${hex}`;
}

export function utf8ToBuffer(utf8: string): Buffer {
  return Buffer.from(aesJs.utils.utf8.toBytes(utf8));
}

export function hexToBuffer(hex: string): Buffer {
  return Buffer.from(aesJs.utils.hex.toBytes(hex));
}

export function arrayToBuffer(arr: Uint8Array): Buffer {
  return Buffer.from(arr);
}

export function bufferToUtf8(buf: Buffer): string {
  return aesJs.utils.utf8.fromBytes(buf);
}

export function bufferToHex(buf: Buffer): string {
  return aesJs.utils.hex.fromBytes(buf);
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
  const enc = isHexString(msg) ? 'hex' : undefined;
  const buf = typeof msg === 'string' ? Buffer.from(msg, enc) : msg;
  return buf;
}
