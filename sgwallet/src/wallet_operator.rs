extern crate star_types;
extern crate crypto;

use star_types::{offchain_transaction::{OffChainTransaction, SignOffChainTransaction, OffChainTransactionInput, OffChainTransactionOutput}};
use crypto::PublicKey;

pub trait WalletOperator {
    fn createAccount() -> PublicKey;
    fn sign(tx:OffChainTransaction) -> SignOffChainTransaction;
    fn executeTx(input:OffChainTransactionInput) -> OffChainTransactionOutput;
    fn applyTx(sign:SignOffChainTransaction);
}