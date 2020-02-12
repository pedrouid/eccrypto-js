import * as eccryptoJS from '../src';

describe('BIP39', () => {
  let mnemonic: string;

  beforeEach(async () => {
    mnemonic = await eccryptoJS.entropyToMnemonic(
      eccryptoJS.randomBytes(eccryptoJS.KEY_LENGTH)
    );
  });

  it('should return mnemonic from entropy', async () => {
    expect(mnemonic).toBeTruthy();
  });
});
