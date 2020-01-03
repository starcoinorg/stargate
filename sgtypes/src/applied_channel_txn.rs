// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::impl_hash;
use crate::signed_channel_transaction::SignedChannelTransaction;
use libra_crypto::ed25519::Ed25519PublicKey;
use libra_crypto::HashValue;
use libra_crypto_derive::CryptoHasher;
use libra_types::account_address::AccountAddress;
use libra_types::transaction::{SignedTransaction, TransactionPayload};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, CryptoHasher)]
pub enum AppliedChannelTxn {
    Offchain(SignedChannelTransaction),
    Travel(SignedTransaction),
}
impl_hash!(AppliedChannelTxn, AppliedChannelTxnHasher);

impl AppliedChannelTxn {
    pub fn channel_sequence_number(&self) -> u64 {
        match self {
            AppliedChannelTxn::Offchain(t) => t.raw_tx.channel_sequence_number(),
            AppliedChannelTxn::Travel(t) => match t.payload() {
                TransactionPayload::Channel(d) => d.channel_sequence_number(),
                _ => panic!("should be channel txn"),
            },
        }
    }
    pub fn participant_keys(&self) -> Vec<Ed25519PublicKey> {
        match self {
            AppliedChannelTxn::Offchain(t) => t
                .signatures
                .values()
                .map(|s| s.public_key.clone())
                .collect(),
            AppliedChannelTxn::Travel(t) => match t.payload() {
                TransactionPayload::Channel(d) => d.public_keys().to_vec(),
                _ => panic!("should be channel txn"),
            },
        }
    }
    pub fn proposer(&self) -> AccountAddress {
        match self {
            AppliedChannelTxn::Offchain(t) => t.raw_tx.proposer(),
            AppliedChannelTxn::Travel(t) => match t.payload() {
                TransactionPayload::Channel(d) => d.proposer(),
                _ => panic!("should be channel txn"),
            },
        }
    }
    pub fn travel(&self) -> bool {
        match self {
            AppliedChannelTxn::Travel(_) => true,
            _ => false,
        }
    }
}
