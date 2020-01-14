#!/bin/sh
 mkdir -p ./proto/{types,sgtypes}
 cd ./proto
 cp -r ../../libra/types/src/proto/*.proto ./types
 cp -r ../../sgtypes/src/proto/*.proto ./sgtypes
 cp ../../node/node_proto/src/proto/node.proto .
echo "get proto ok!"