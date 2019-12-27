#!/bin/sh
# Copyright (c) The Libra Core Contributors
# SPDX-License-Identifier: Apache-2.0
set -e

OUT_DIR="${1?[Specify relative output directory]}"
shift

LIBRA_DIR="$(cd ./libra && pwd)"
TF_WORK_DIR="$(cd ./sgterraform/sgchain && pwd)"
OUTPUT_DIR="$TF_WORK_DIR/$OUT_DIR"
mkdir -p "$OUTPUT_DIR"


if [ ! -e "$OUTPUT_DIR/mint.key" ]; then
	cd $LIBRA_DIR && cargo run -p generate-keypair --bin generate-keypair -- -o "$OUTPUT_DIR/mint.key"
fi

cd $LIBRA_DIR && cargo run -p config-builder --bin config-builder --  -m "$OUTPUT_DIR/mint.key" -o "$OUTPUT_DIR/val" -d -r validator "$@"

# mv config & clear dir
cd "$OUTPUT_DIR/val"
mv */*.keys.toml .
mv 0/*.network_peers.config.toml network_peers.config.toml
mv 0/consensus_peers.config.toml ../consensus_peers.config.toml
mv 0/genesis.blob ../
rm */*.toml */*.blob
find . -mindepth 1 -type d -print0 | xargs -0 rmdir
