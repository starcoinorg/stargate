#!/usr/bin/env bash
### A Script to generate api doc from protos.
### You need install document generate tools from github.
### https://github.com/pseudomuto/protoc-gen-doc

mkdir -p docs/api
protoc -I=libra/types/src/proto -I=node/node_proto/src/proto -I=sgtypes/src/proto  --doc_out=docs/api --doc_opt=html,node.html node.proto
