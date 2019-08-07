fn main() {
    let proto_root = "src/proto";
    //let type_root = "../../types/src/proto";
    //let sg_type_root = "../../star_types/src/proto";

    build_helpers::build_helpers::compile_proto(
        proto_root,
        vec![],
        true, /* generate_client_stub */
    );
}
