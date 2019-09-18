use hex;

use canonical_serialization::{CanonicalSerialize, SimpleDeserializer, SimpleSerializer};
use types::account_config::{account_struct_tag, AccountResource};
use types::event::EventHandle;

use crate::resource::*;

use super::*;
use types::account_address::AccountAddress;
use crate::account_resource_ext::new_account_for_test;

#[test]
fn test_resource() {
    let account_resource = AccountResource::new(100, 1, types::byte_array::ByteArray::new(vec![]), false, EventHandle::random_handle(0),
                                                EventHandle::random_handle(0));

    let out: Vec<u8> = SimpleSerializer::serialize(&account_resource).unwrap();
    println!("resource hex: {}", hex::encode(&out));

    let resource = Resource::new_from_account_resource(account_resource);
    println!("resource:{:#?}", resource);
    let out2: Vec<u8> = resource.encode();
    assert_eq!(out, out2)
}
