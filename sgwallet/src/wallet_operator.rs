extern crate star_types;
extern crate crypto;

use star_types::{channel::SgChannelState, offchain_transaction::{OffChainTransaction, SignOffChainTransaction, OffChainTransactionInput, OffChainTransactionOutput}};
use crypto::PublicKey;

pub trait WalletOperator {
    fn create_account() -> PublicKey;
    fn sign(tx: OffChainTransaction) -> SignOffChainTransaction;
    fn execute_tx(input: OffChainTransactionInput) -> OffChainTransactionOutput;
    fn apply_tx(sign: SignOffChainTransaction);
    fn channel_state() -> SgChannelState;
}