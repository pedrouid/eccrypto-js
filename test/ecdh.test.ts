import { compare, testSharedKeys } from './common';

describe('ECDH', () => {
  let sharedKey1: Buffer;
  let sharedKey2: Buffer;

  beforeEach(async () => {
    const sharedKeys = await testSharedKeys();
    sharedKey1 = sharedKeys.sharedKey1;
    sharedKey2 = sharedKeys.sharedKey2;
  });

  it('should derive shared keys succesfully', () => {
    expect(sharedKey1).toBeTruthy();
    expect(sharedKey2).toBeTruthy();
  });

  it('derived shared keys should match', () => {
    const isMatch = compare(sharedKey1, sharedKey2);
    expect(isMatch).toBeTruthy();
  });
});
