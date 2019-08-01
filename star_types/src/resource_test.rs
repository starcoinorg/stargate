use hex;

use canonical_serialization::{CanonicalSerialize, SimpleDeserializer, SimpleSerializer};
use types::account_config::{account_struct_tag, AccountResource};
use vm_runtime_types::loaded_data::struct_def::StructDef;
use vm_runtime_types::loaded_data::types::Type;

use crate::resource::*;

use super::*;

#[test]
fn test_resource() {
    let account_resource = AccountResource::new(100, 1, types::byte_array::ByteArray::new(vec![]), 0, 0, false);
    let mut serializer = SimpleSerializer::new();
    account_resource.serialize(&mut serializer).unwrap();
    let out: Vec<u8> = serializer.get_output();
    println!("resource hex: {}", hex::encode(&out));

    let mut deserializer = SimpleDeserializer::new(out.as_slice());

    let resource = Resource::decode(account_struct_tag(), get_account_struct_def(), &mut deserializer).expect("decode fail.");
    println!("resource:{:#?}", resource);
    let mut serializer = SimpleSerializer::new();
    resource.serialize(&mut serializer).expect("serialize resource fail.");
    let out2: Vec<u8> = serializer.get_output();
    assert_eq!(out, out2)
}

fn get_account_struct_def() -> StructDef {
    let int_type = Type::U64;
    let byte_array_type = Type::ByteArray;
    let coin = Type::Struct(StructDef::new(vec![int_type.clone()]));
    StructDef::new(vec![
        byte_array_type,
        coin,
        Type::Bool,
        int_type.clone(),
        int_type.clone(),
        int_type.clone(),
    ])
}