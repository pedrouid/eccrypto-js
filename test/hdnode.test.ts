import * as eccryptoJS from '../src';

describe('HDNode', () => {
  let hdNode: eccryptoJS.HDNode;

  beforeEach(async () => {
    hdNode = await eccryptoJS.HDNode.createRandom();
  });

  it('should instantiate an HDNode succesfully', async () => {
    expect(hdNode).toBeTruthy();
  });
});
