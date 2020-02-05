import aesJs from 'aes-js';

export function removeTrailing0x(str: string) {
  if (str.startsWith('0x')) {
    return str.substring(2);
  } else {
    return str;
  }
}

export function addTrailing0x(str: string) {
  if (!str.startsWith('0x')) {
    return '0x' + str;
  } else {
    return str;
  }
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
