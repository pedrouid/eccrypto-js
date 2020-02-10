export function compare(buf1: Buffer, buf2: Buffer) {
  return buf1.toString('hex') === buf2.toString('hex');
}

export async function prettyPrint(name: string, obj: any) {
  const displayObject: any = {};
  Object.keys(obj).forEach((key: string) => {
    const value = Buffer.isBuffer(obj[key])
      ? obj[key].toString('hex')
      : obj[key];
    displayObject[key] = value;
  });
  console.log(name, JSON.stringify(displayObject, null, 2));
}
