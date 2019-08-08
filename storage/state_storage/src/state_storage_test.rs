use std::thread;

use canonical_serialization::{CanonicalDeserialize, CanonicalSerialize, SimpleDeserializer, SimpleSerializer};
use types::account_config::AccountResource;

use super::*;

#[test]
fn test_state_storage() {
    let mut storage = StateStorage::new();
    let account_address = AccountAddress::random();
    let init_amount = 100;
    storage.create_account(account_address, init_amount);
    let account_state = storage.get_account_state(&account_address).unwrap();
    //let resource = AccountResource::default();
    //let mut serializer = SimpleSerializer::new();
    //resource.serialize(&mut serializer);
    let access_path = AccessPath::new_for_account(account_address);

    let resource_bytes: Vec<u8> = storage.get_by_access_path(&access_path).unwrap();  //serializer.get_output();

    let mut deserializer = SimpleDeserializer::new(resource_bytes.as_slice());
    let resource = AccountResource::deserialize(&mut deserializer).unwrap();
    assert_eq!(init_amount, resource.balance());

    let resource_bytes2 = account_state.get(&access_path.path).unwrap();

    //let root_hash = storage.update(&access_path, resource_bytes.clone()).expect("update fail.");
    //assert_eq!(root_hash, storage.root_hash());

//    let account_state = storage.get_account_state(&account_address).unwrap();
//    let resource_bytes2 = account_state.get(&access_path.path).expect("get fail.");
    assert_eq!(resource_bytes, resource_bytes2);
//    let account_bytes = account_state.to_bytes();
//    debug_assert!(account_bytes.len() > 0);

    storage.delete(&access_path).unwrap();
    debug_assert!(storage.get_by_access_path(&access_path).is_none())
}

#[test]
fn test_multi_thread() {
    let storage = StateStorage::new();
    thread::spawn(move || {
        println!("{:#?}", storage.root_hash())
    });
}