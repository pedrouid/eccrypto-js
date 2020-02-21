import * as eccryptoJS from '../src';
import { TEST_MNEMONIC, TEST_XPUB } from './common/constants';

describe('HDNode', () => {
  it('should create from random an HDNode succesfully', async () => {
    const hdNode = eccryptoJS.HDNode.createRandom();
    expect(hdNode).toBeTruthy();
  });

  it('should create from extended key HDNode succesfully', async () => {
    const hdNode = eccryptoJS.HDNode.fromMasterSeed(TEST_MNEMONIC);
    expect(hdNode).toBeTruthy();
  });

  it('should create from extended key HDNode succesfully', async () => {
    const hdNode = eccryptoJS.HDNode.fromExtendedKey(TEST_XPUB);
    expect(hdNode).toBeTruthy();
    expect(hdNode.xpub === TEST_XPUB).toBeTruthy();
  });
});
