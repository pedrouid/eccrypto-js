/**
 * Returns the subarray of a Uint8Array without PKCS#7 padding.
 *
 * @param padded {Uint8Array} unencrypted bytes that have been padded
 * @return {Uint8Array} the unpadded bytes
 * @see http://tools.ietf.org/html/rfc5652
 */
export default function unpad(padded: Uint8Array): Uint8Array {
  return padded.subarray(0, padded.byteLength - padded[padded.byteLength - 1]);
}
