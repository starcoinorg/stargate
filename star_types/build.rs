// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

fn main() {
    let proto_files = [
        "src/proto/channel_transaction.proto",
        "src/proto/message.proto",
        "src/proto/node.proto",
        "src/proto/script_package.proto",
        "src/proto/star_account.proto",
    ];

    let includes = [
        "../libra/types/src/proto",
        "src/proto",
    ];

    prost_build::compile_protos(&proto_files, &includes).unwrap();
}
