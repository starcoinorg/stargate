#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

declare -a libra_crates=("types" "config" "common/build_helpers" "common/canonical_serialization" "common/failure_ext" "common/grpc_helpers" "common/grpcio-client" "common/grpcio-extras" "common/logger" "common/metrics" "common/proptest_helpers" "common/proto_conv" "crypto/legacy_crypto" "crypto/nextgen_crypto" "storage/accumulator" "storage/sparse_merkle" "storage/state_view" "language/vm" "language/bytecode_verifier" "language/compiler" "language/stdlib")

echo "Update git submodule"
git submodule init
git submodule update

git submodule foreach git pull origin master

## now loop through the above array
for crate in "${libra_crates[@]}"
do
  FROM="$DIR/libra/$crate/"
  TO="$DIR/$crate"
  echo "sync $FROM with $TO";
  rsync -avu --delete "$FROM" "$TO"
done

git status