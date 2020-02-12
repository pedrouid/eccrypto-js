const path = require('path');

module.exports = {
  mode: 'production',
  entry: {
    index: './dist/index.js',
  },
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].min.js',
    libraryTarget: 'umd',
    library: 'eccryptoJS',
    umdNamedDefine: true,
    globalObject: 'this',
  },
  resolve: {
    extensions: ['.js'],
  },
  devtool: 'source-map',
  optimization: {
    minimize: true,
  },
};
