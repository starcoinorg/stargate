// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::resource::Resource;
use hex;

use canonical_serialization::SimpleSerializer;
use libra_types::{account_config::AccountResource, event::EventHandle};
use libra_types::account_address::AccountAddress;
use libra_types::identifier::{Identifier, IdentStr};
use libra_types::language_storage::StructTag;

use vm_runtime_types::value::{Value, Struct};
use vm_runtime_types::native_structs::vector::NativeVector;
use vm_runtime_types::native_functions::dispatch::NativeReturnStatus;
use vm_runtime_types::loaded_data::types::Type;
use proptest::std_facade::VecDeque;

#[test]
fn test_account_resource() {
    let account_resource = AccountResource::new(
        100,
        1,
        libra_types::byte_array::ByteArray::new(vec![]),
        false,
        false,
        EventHandle::random_handle(0),
        EventHandle::random_handle(0),
    );

    let out: Vec<u8> = SimpleSerializer::serialize(&account_resource).unwrap();
    println!("resource hex: {}", hex::encode(&out));

    let resource = Resource::new_from_account_resource(account_resource);
    println!("resource:{:#?}", resource);
    let out2: Vec<u8> = resource.encode();
    assert_eq!(out, out2)
}

#[test]
fn test_vector_resource() {
    let struct_tag = StructTag {
        address: AccountAddress::default(),
        module: Identifier::from(IdentStr::new("Test").unwrap()),
        name: Identifier::from(IdentStr::new("T").unwrap()),
        type_params: vec![],
    };
    let field0 = match NativeVector::native_empty(VecDeque::new()){
        NativeReturnStatus::Success{cost: _cost, mut return_values} => {
            return_values.pop().unwrap()
        }
        _ => {
            panic!("create native vector fail.");
        }
    };
    let s: Struct = Struct::new(vec![field0]);
    let value = Value::struct_(s.clone());
    let struct_def = match value.to_type_FOR_TESTING(){
        Type::Struct(def) => def,
        _ => {
            panic!("expect struct type");
        }
    };
    let resource = Resource::new(struct_tag.clone(), s);

    let bytes = resource.encode();
    let resource1 = Resource::decode(struct_tag, struct_def, bytes.as_slice()).unwrap();
    assert_eq!(resource, resource1);

}
