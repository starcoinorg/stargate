fn main() {
    let protos = ["src/proto/faucet.proto"];

    let includes = ["src/proto/"];

    grpcio_compiler::prost_codegen::compile_protos(
        &protos,
        &includes,
        &std::env::var("OUT_DIR").unwrap(),
    )
    .unwrap();
}
