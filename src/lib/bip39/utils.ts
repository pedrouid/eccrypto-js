import { isNode, nodeSha256 } from '../node';
import { fallbackSha256 } from '../fallback';

function sha256Sync(buf) {
  if (isNode()) {
    return nodeSha256(buf);
  }
  return fallbackSha256(buf);
}

export function normalize(str?: string): string {
  return (str || '').normalize('NFKD');
}

export function lpad(str: string, padString: string, length: number): string {
  while (str.length < length) str = padString + str;
  return str;
}

export function binaryToByte(bin: string): number {
  return parseInt(bin, 2);
}

export function bytesToBinary(bytes: number[]): string {
  return bytes.map(x => lpad(x.toString(2), '0', 8)).join('');
}

export function deriveChecksumBits(entropyBuffer: Buffer): string {
  const ENT = entropyBuffer.length * 8;
  const CS = ENT / 32;
  const hash = sha256Sync(entropyBuffer);

  return bytesToBinary(Array.from(hash)).slice(0, CS);
}
