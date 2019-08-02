fn main() {
    let proto_root = "src/proto";
    //let dependent_root = "../../types/src/proto";

    build_helpers::build_helpers::compile_proto(
        proto_root,
        vec![],
        true, /* generate_client_stub */
    );
}
