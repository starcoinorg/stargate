use crypto::HashValue;
use scratchpad::Accumulator;
use std::{collections::BTreeMap,sync::{Arc}};
use types::transaction::{SignedTransaction, TransactionInfo, Version};
use types::proof::position::Position;
use crate::storage::TransactionStorage;

struct TransactionStorageImpl {
//    version:Arc<ReadWriteLock<Version>>,
    signedTxMap: BTreeMap<u64, SignedTransaction>,
    txInfoMap: BTreeMap<u64, TransactionInfo>,
    accumulatorMap: BTreeMap<Position, HashValue>,
}

impl TransactionStorage for TransactionStorageImpl {
    fn insertSignedTransaction(tx: SignedTransaction) {
        unimplemented!()
    }
    fn insertTransactionInfo(tx: TransactionInfo) {
        unimplemented!()
    }
    fn insertAccumulatorRoot(position: Position, root: HashValue) {
        unimplemented!()
    }
}