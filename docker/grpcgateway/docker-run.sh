#!/bin/sh
# Copyright (c) The Libra Core Contributors
# SPDX-License-Identifier: Apache-2.0
set -ex

cd /gateway/proto
#ls -a -R .
protoc -I. -I./types -I./sgtypes \
           --go_out=plugins=grpc,paths=source_relative:../node \
           ./node.proto

protoc -I. -I./types -I./sgtypes \
           --grpc-gateway_out=logtostderr=true:../node \
           ./node.proto

protoc -I. -I./types -I./sgtypes \
           --swagger_out=logtostderr=true:../ \
           ./node.proto

cd /gateway/proto/sgtypes
for file in *.proto
do
    DIRECTORY=$(dirname ${file})
    #echo "Generating protos from ${file}, into ${DIRECTORY}"

    protoc -I. -I../types \
           --go_out=plugins=grpc,paths=source_relative:../../sgtypes \
           ${file}
done

cd /gateway/proto/types
for file in *.proto
do
    DIRECTORY=$(dirname ${file})
    #echo "Generating protos from ${file}, into ${DIRECTORY}"

    protoc -I. \
           --go_out=plugins=grpc,paths=source_relative:../../libra/types \
           ${file}
done
# start gateway
cd /gateway
exec go run gateway.go -gateway_addr $GATEWAY_PORT -node_addr $NODE_PORT --log_dir=./log
