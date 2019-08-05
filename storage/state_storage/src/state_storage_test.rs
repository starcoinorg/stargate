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
    let bytes: Vec<u8> = serializer.get_output();
    let access_path = AccessPath::new_for_account_resource(account_address.clone());
    let root_hash = storage.update(access_path.clone(), bytes.clone()).expect("update fail.");
    let account_state = storage.get_account_state(&account_address).unwrap();
    let bytes2 = account_state.get(&access_path.path).expect("get fail.");
    assert_eq!(bytes, bytes2);
}

#[test]
fn test_multi_thread(){
    let mut storage = StateStorage::new();
    thread::spawn(move ||{
        println!("{:#?}", storage.root_hash())
    });
}