import * as eccryptoJS from '../src';

const TEST_XPUB =
  'xpub661MyMwAqRbcF1NXmnu4rokqZZ6MJPSVdUbzf7eGrbLs6yXsG6ZBmHhSKFhiJkGjaeU1xB1vdEekfZYvtkMDzgya6QrqoPySGeouYYRjCpP';

describe('HDNode', () => {
  it('should create from random an HDNode succesfully', async () => {
    const hdNode = await eccryptoJS.HDNode.createRandom();
    console.log('hdNode.xpub', hdNode.xpub);
    expect(hdNode).toBeTruthy();
  });

  it('should create from random an HDNode succesfully', async () => {
    const hdNode = await eccryptoJS.HDNode.createRandom();
    expect(hdNode).toBeTruthy();
  });
});
