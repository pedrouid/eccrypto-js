const path = require('path');

module.exports = {
  mode: 'production',
  entry: {
    index: path.resolve(__dirname, 'dist', 'esm', 'index.js'),
  },
  output: {
    path: path.resolve(__dirname, 'dist', 'umd'),
    filename: '[name].min.js',
    libraryTarget: 'umd',
    library: 'eccryptoJS',
    umdNamedDefine: true,
    globalObject: 'this',
  },
  resolve: {
    extensions: ['.js'],
  },
  optimization: {
    minimize: true,
  },
};
