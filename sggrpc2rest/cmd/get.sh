#!/bin/sh
 cd ./proto
 rm -rf types
 rm -rf sgtypes
 mkdir types sgtypes
 cp -r ../../libra/types/src/proto/*.proto ./types
 cp -r ../../sgtypes/src/proto/*.proto ./sgtypes
 cp ../../node/node_proto/src/proto/node.proto .
echo "get proto ok!"