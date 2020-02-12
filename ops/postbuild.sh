# rename dist files
cp ./dist/index.umd.production.min.js ./dist/index.js 
cp ./dist/index.umd.production.min.js.map ./dist/index.js.map

# delete duplicates
rm -rf ./dist/index.umd.*