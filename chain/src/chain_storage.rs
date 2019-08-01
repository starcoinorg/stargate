use crypto::HashValue;
use sparse_merkle::node_type::Node;
use std::collections::BTreeMap;
use types::transaction::{SignedTransaction, TransactionInfo};
use types::proof::position::Position;
use crate::storage::TransactionStorage;

struct TransactionStorageImpl {
    signedTxs:BTreeMap<u64, SignedTransaction>,
    infoTxs:BTreeMap<u64, TransactionInfo>,
    accumulator:BTreeMap<Position, HashValue>
}

impl TransactionStorage for TransactionStorageImpl {
    fn insertTx(tx:SignedTransaction) {
        unimplemented!()
    }
}