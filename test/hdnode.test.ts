import * as eccryptoJS from '../src';

describe('HDNode', () => {
  let hdNode: eccryptoJS.HDNode;

  beforeEach(async () => {
    hdNode = new eccryptoJS.HDNode();
  });

  it('should instantiate an HDNode succesfully', async () => {
    expect(hdNode).toBeTruthy();
  });
});
