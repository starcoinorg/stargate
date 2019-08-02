use types::{transaction::{SignedTransaction, TransactionInfo}, proof::position::Position};
use crypto::HashValue;

pub trait TransactionStorage {
    fn insertSignedTransaction(tx: SignedTransaction);
    fn insertTransactionInfo(tx: TransactionInfo);
    fn insertAccumulatorRoot(position: Position, root: HashValue);
}