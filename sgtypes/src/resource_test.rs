use hex;

use canonical_serialization::{SimpleSerializer};
use libra_types::{
    account_config::{AccountResource},
    event::EventHandle,
};
use crate::resource::*;

#[test]
fn test_resource() {
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
