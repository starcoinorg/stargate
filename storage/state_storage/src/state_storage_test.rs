use super::*;
use canonical_serialization::{CanonicalDeserialize, SimpleDeserializer};
use types::account_config::AccountResource;
use vm_genesis::{encode_genesis_transaction, encode_create_account_program, GENESIS_KEYPAIR};
use types::{transaction::{RawTransaction, TransactionPayload}, account_config::{core_code_address, association_address}};
use std::convert::TryInto;
use std::thread;
use std::thread::sleep;
use std::time::Duration;
use vm_runtime::{MoveVM, VMExecutor};
use config::config::{VMConfig, VMPublishingOption};

#[test]
fn test_state_storage() {
    let mut storage = test_genesis_transaction();
    let account_address = AccountAddress::random();
    let init_amount = 100;
    //storage.create_account(account_address, init_amount);

    let sender = association_address();
    let s_n = match storage.sequence_number(&sender) {
        Some(num) => num,
        _ => 0
    };
    let signed_tx = RawTransaction::new(
        sender,
        s_n,
        encode_create_account_program(&account_address, init_amount),
        1000_000 as u64,
        1 as u64,
        Duration::from_secs(u64::max_value()),
    ).sign(&GENESIS_KEYPAIR.0, GENESIS_KEYPAIR.1.clone())
        .unwrap()
        .into_inner();

    let vm_config = VMConfig::onchain();

    let mut output_vec = MoveVM::execute_block(vec![signed_tx], &vm_config, &storage);

    storage.apply_libra_output(&output_vec.pop().unwrap());

    let account_state_blob = storage.get_account_state(&account_address).unwrap();
    let account_state = AccountState::from_account_state_blob(account_state_blob).unwrap();
    let resource = account_state.get_account_resource().unwrap();
    assert_eq!(resource.balance(), init_amount);
    let access_path = AccessPath::new_for_account(account_address);

    let resource_bytes: Vec<u8> = storage.get_by_access_path(&access_path).unwrap();  //serializer.get_output();

    let mut deserializer = SimpleDeserializer::new(resource_bytes.as_slice());
    let resource1 = AccountResource::deserialize(&mut deserializer).unwrap();
    assert_eq!(resource.balance(), resource1.balance());

    let resource_bytes2 = storage.get(&access_path).unwrap().unwrap();

    //let root_hash = storage.update(&access_path, resource_bytes.clone()).expect("update fail.");
    //assert_eq!(root_hash, storage.root_hash());

//    let account_state = storage.get_account_state(&account_address).unwrap();
//    let resource_bytes2 = account_state.get(&access_path.path).expect("get fail.");
    assert_eq!(resource_bytes, resource_bytes2);
//    let account_bytes = account_state.to_bytes();
//    debug_assert!(account_bytes.len() > 0);

//    storage.delete(&access_path).unwrap();
//    debug_assert!(storage.get_by_access_path(&access_path).is_none())
}

#[test]
fn test_multi_thread() {
    let mut storage = test_genesis_transaction();
    thread::spawn(move || {
        println!("{:#?}", storage.root_hash())
    });
    sleep(Duration::from_millis(1_000))
}


fn test_genesis_transaction() -> StateStorage {
    let genesis_checked_txn = encode_genesis_transaction(&GENESIS_KEYPAIR.0, GENESIS_KEYPAIR.1.clone());
    let genesis_txn = genesis_checked_txn.into_inner();
    let mut storage = StateStorage::new();
    if let TransactionPayload::WriteSet(write_set) = genesis_txn.payload() {
        storage.apply_write_set( &write_set).unwrap();
    }
    storage
}

#[test]
fn test_genesis_tx() {
    let mut storage = test_genesis_transaction();
    let account = AccountAddress::default();
    let account_state = storage.get_account_state(&account).unwrap();
    let map: BTreeMap<Vec<u8>, Vec<u8>> = (&AccountStateBlob::from(account_state)).try_into().unwrap();
    println!("{:?}", map);
}