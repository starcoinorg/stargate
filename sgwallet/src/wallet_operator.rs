extern crate star_types;
extern crate crypto;

use star_types::{channel::SgChannelState, offchain_transaction::{OffChainTransaction, SignOffChainTransaction, OffChainTransactionInput, OffChainTransactionOutput}};
use crypto::PublicKey;

pub trait WalletOperator {
    fn createAccount() -> PublicKey;
    fn sign(tx: OffChainTransaction) -> SignOffChainTransaction;
    fn executeTx(input: OffChainTransactionInput) -> OffChainTransactionOutput;
    fn applyTx(sign: SignOffChainTransaction);
    fn channelState() -> SgChannelState;
}