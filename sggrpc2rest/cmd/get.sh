#!/bin/sh
 cd ../proto
 rm -rf types/*
 rm -rf sgtypes/*
 cp -r ~/work/project/rust/stargate/libra/types/src/proto/*.proto ./types
 cp -r ~/work/project/rust/stargate/sgtypes/src/proto/*.proto ./sgtypes
 cp ../../node/node_proto/src/proto/node.proto .
echo "get proto ok!"