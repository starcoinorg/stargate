use crypto::HashValue;
use types::proof::accumulator::Accumulator;
use std::{collections::HashMap};
use types::transaction::{SignedTransaction, TransactionInfo, Version};
use crypto::hash::{CryptoHash, TransactionInfoHasher};
use types::vm_error::StatusCode;

pub struct TransactionStorage {
    signed_tx_vec: Vec<SignedTransaction>,
    signed_tx_hash_map: HashMap<HashValue, Version>,
    tx_info_vec: Vec<TransactionInfo>,
    ledger_info_vec: Vec<HashValue>,
    //Ledger Info(Position:Accumulator Root Hash)
    accumulator: Accumulator<TransactionInfoHasher>,//全局唯一的accumulator，用于计算Accumulator Root Hash
}

impl TransactionStorage {
    pub fn new() -> Self {
        TransactionStorage { signed_tx_vec: vec![], signed_tx_hash_map: HashMap::new(), tx_info_vec: vec![], ledger_info_vec: vec![], accumulator: Accumulator::new(vec![], 0).unwrap() }
    }

    pub fn exist_signed_transaction(&self, key: HashValue) -> bool {
        self.signed_tx_hash_map.contains_key(&key)
    }

    pub fn insert_signed_transaction(&mut self, tx: SignedTransaction) -> Version {
        self.signed_tx_vec.push(tx.clone());
        let version = (self.signed_tx_vec.len() - 1) as u64;
        self.signed_tx_hash_map.insert(tx.hash(), version);
        version
    }

    pub fn get_signed_transaction_by_hash(&self, key: &HashValue) -> Option<SignedTransaction> {
        self.signed_tx_hash_map.get(key).and_then(|ver| -> Option<SignedTransaction> {
            let data = self.signed_tx_vec.get(ver.clone() as usize);
            match data {
                Some(signed_tx) => { Some(signed_tx.clone()) }
                None => None
            }
        })
    }

    pub fn insert_transaction_info(&mut self, tx: TransactionInfo) {
        self.tx_info_vec.push(tx)
    }

    pub fn insert_ledger_info(&mut self, root: HashValue) {
        self.ledger_info_vec.push(root)
    }

    pub fn accumulator_append(&self, tx_info: TransactionInfo) -> HashValue {
        self.accumulator.append(vec![tx_info.hash()]).root_hash()
    }

    pub fn insert_tx(&mut self, state_hash: HashValue, event_hash: HashValue, sign_tx: SignedTransaction) -> Version {
        let signed_tx_hash = sign_tx.clone().hash();
        let version = self.insert_signed_transaction(sign_tx.clone());

        let tx_info = TransactionInfo::new(signed_tx_hash, state_hash, event_hash, 0, StatusCode::EXECUTED);
        self.insert_transaction_info(tx_info.clone());

        let hash_root = self.accumulator_append(tx_info);
        self.insert_ledger_info(hash_root);
        version
    }

    pub fn least_version(&self) -> Version {
        let tmp = self.signed_tx_vec.len() as u64;
        if tmp > 0 {
            tmp - 1
        } else {
            0
        }
    }

    pub fn least_hash_root(&self) -> HashValue {
        let version = self.least_version();
        *(self.ledger_info_vec.get(version as usize).unwrap()) as HashValue
    }
}