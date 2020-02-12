import { sha256 } from '../../sha2';

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

export async function deriveChecksumBits(
  entropyBuffer: Buffer
): Promise<string> {
  const ENT = entropyBuffer.length * 8;
  const CS = ENT / 32;
  const hash = await sha256(entropyBuffer);

  return bytesToBinary(Array.from(hash)).slice(0, CS);
}
