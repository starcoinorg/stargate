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

    let out: Vec<u8> = SimpleSerializer::serialize(&account_resource).unwrap();
    println!("resource hex: {}", hex::encode(&out));

    let resource = Resource::new_from_account_resource(account_resource);
    println!("resource:{:#?}", resource);
    let out2: Vec<u8> = resource.encode();
    assert_eq!(out, out2)
}

#[test]
fn test_resource_diff_and_apply(){
    let mut account_resource = Resource::new_from_account_resource(AccountResource::new(100, 1, types::byte_array::ByteArray::new(vec![]), 0, 0, false));
    let account_resource2 = Resource::new_from_account_resource(AccountResource::new(200, 1, types::byte_array::ByteArray::new(vec![]), 0, 0, false));

    let mut changes = account_resource.diff(&account_resource2).unwrap();
    println!("changes:{:#?}", changes);
    changes.filter_none();
    assert_eq!(1, changes.len());

    account_resource.apply_changes(changes).unwrap();
    assert_eq!(account_resource, account_resource2);
}
