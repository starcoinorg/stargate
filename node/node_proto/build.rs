// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

fn main() {
    let proto_files = ["src/proto/node.proto"];

    let includes = [
        "../../libra/types/src/proto",
        "../../sgtypes/src/proto",
        "src/proto",
    ];

    grpcio_compiler::prost_codegen::compile_protos(
        &proto_files,
        &includes,
        &std::env::var("OUT_DIR").unwrap(),
    )
    .unwrap();
}
