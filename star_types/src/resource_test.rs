use hex;

use canonical_serialization::{CanonicalSerialize, SimpleDeserializer, SimpleSerializer};
use types::account_config::{account_struct_tag, AccountResource, EventHandle};
use vm_runtime_types::loaded_data::struct_def::StructDef;
use vm_runtime_types::loaded_data::types::Type;

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

#[test]
fn test_resource_diff_and_apply() {
    let account_address = AccountAddress::random();
    let event_handle = EventHandle::new_from_address(&account_address, 0);
    let mut account_resource = Resource::new_from_account_resource(new_account_for_test(100));
    let account_resource2 = Resource::new_from_account_resource(new_account_for_test(200));

    let mut changes = account_resource.diff(&account_resource2).unwrap();
    println!("changes:{:#?}", changes);
    changes.filter_none();
    assert_eq!(1, changes.len());

    account_resource.apply_changes(&changes).unwrap();
    assert_eq!(account_resource, account_resource2);
}
