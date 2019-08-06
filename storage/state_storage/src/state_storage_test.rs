use canonical_serialization::{CanonicalSerialize, SimpleSerializer};
use types::account_config::AccountResource;

use super::*;
use std::thread;

#[test]
fn test_state_storage() {
    let mut storage = StateStorage::new();
    let account_address = AccountAddress::random();
    storage.create_account(account_address);
    let resource = AccountResource::default();
    let mut serializer = SimpleSerializer::new();
    resource.serialize(&mut serializer);
    let resource_bytes: Vec<u8> = serializer.get_output();
    let access_path = AccessPath::new_for_account_resource(account_address.clone());
    let root_hash = storage.update(access_path.clone(), resource_bytes.clone()).expect("update fail.");
    let account_state = storage.get_account_state(&account_address).unwrap();
    let resource_bytes2 = account_state.get(&access_path.path).expect("get fail.");
    assert_eq!(resource_bytes, resource_bytes2);
    let account_bytes = account_state.to_bytes();
    debug_assert!(account_bytes.len() > 0);
}

#[test]
fn test_multi_thread(){
    let storage = StateStorage::new();
    thread::spawn(move ||{
        println!("{:#?}", storage.root_hash())
    });
}