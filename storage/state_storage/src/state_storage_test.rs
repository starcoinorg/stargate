use super::*;
use canonical_serialization::{CanonicalDeserialize, SimpleDeserializer};
use types::account_config::AccountResource;
use vm_genesis::{encode_genesis_transaction, GENESIS_KEYPAIR};
use types::transaction::TransactionPayload;
use std::convert::TryInto;
use std::thread;

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

    let resource_bytes2 = storage.get(&access_path).unwrap().unwrap();

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

#[test]
fn test_genesis_tx(){
    let genesis_checked_txn = encode_genesis_transaction(&GENESIS_KEYPAIR.0, GENESIS_KEYPAIR.1.clone());
    let genesis_txn = genesis_checked_txn.into_inner();
    let mut storage = StateStorage::new();
    if let TransactionPayload::WriteSet(write_set)  = genesis_txn.payload(){
        storage.apply_write_set(write_set).unwrap();
    }
    let account = AccountAddress::default();
    let account_state = storage.get_account_state(&account).unwrap();
    let map:BTreeMap<Vec<u8>,Vec<u8>> = (&AccountStateBlob::from(account_state)).try_into().unwrap();
    println!("{:?}", map);
}