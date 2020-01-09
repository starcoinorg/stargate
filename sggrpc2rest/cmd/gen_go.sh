#!/bin/sh
cd ./proto
echo "generate node pb..."
protoc -I. -I./types -I./sgtypes \
           -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
           --go_out=plugins=grpc,paths=source_relative:../node \
           ./node.proto
echo "generate node pb OK!"

protoc -I. -I./types -I./sgtypes \
           -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
           --grpc-gateway_out=logtostderr=true:../node \
           ./node.proto
echo "generate node gateway OK!"

protoc -I. -I./types -I./sgtypes \
           -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
           --swagger_out=logtostderr=true:../ \
           ./node.proto
echo "generate node rest api swagger OK!"

cd ../proto/sgtypes
for file in *.proto
do
    DIRECTORY=$(dirname ${file})
    echo "Generating protos from ${file}, into ${DIRECTORY}"

    protoc -I. -I../types \
           -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
           --go_out=plugins=grpc,paths=source_relative:../../sgtypes \
           ${file}
done
echo "generate types OK!"

cd ../types
for file in *.proto
do
    DIRECTORY=$(dirname ${file})
    echo "Generating protos from ${file}, into ${DIRECTORY}"

    protoc -I. \
           -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
           --go_out=plugins=grpc,paths=source_relative:../../libra/types \
           ${file}
done

echo "generate sgtypes OK!"
