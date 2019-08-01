extern crate crypto;

use crypto::Signature;

pub struct OffChainTransaction {}

pub struct OffChainTransactionInput {}

pub struct OffChainTransactionOutput {}

pub struct SignOffChainTransaction {
    sign: Signature,
    data: OffChainTransaction,
}