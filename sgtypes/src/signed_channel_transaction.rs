// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    channel_transaction::ChannelTransaction, channel_transaction_sigs::ChannelTransactionSigs,
    hash::SignedChannelTransactionHasher, impl_hash,
};
use failure::prelude::*;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedChannelTransaction {
    pub raw_tx: ChannelTransaction,
    pub sender_signature: ChannelTransactionSigs,
    pub receiver_signature: ChannelTransactionSigs,
}

impl SignedChannelTransaction {
    pub fn new(
        raw_tx: ChannelTransaction,
        sender_signature: ChannelTransactionSigs,
        receiver_signature: ChannelTransactionSigs,
    ) -> Self {
        Self {
            raw_tx,
            sender_signature,
            receiver_signature,
        }
    }
}

impl_hash!(SignedChannelTransaction, SignedChannelTransactionHasher);

impl TryFrom<crate::proto::sgtypes::SignedChannelTransaction> for SignedChannelTransaction {
    type Error = Error;

    fn try_from(
        signed_transaction: crate::proto::sgtypes::SignedChannelTransaction,
    ) -> Result<Self> {
        let raw_tx = ChannelTransaction::try_from(signed_transaction.raw_tx.unwrap())?;
        let sender_signature =
            ChannelTransactionSigs::try_from(signed_transaction.sender_signature.unwrap())?;
        let receiver_signature =
            ChannelTransactionSigs::try_from(signed_transaction.receiver_signature.unwrap())?;
        Ok(SignedChannelTransaction {
            raw_tx,
            sender_signature,
            receiver_signature,
        })
    }
}

impl From<SignedChannelTransaction> for crate::proto::sgtypes::SignedChannelTransaction {
    fn from(signed_transaction: SignedChannelTransaction) -> Self {
        Self {
            raw_tx: Some(signed_transaction.raw_tx.into()),
            sender_signature: Some(signed_transaction.sender_signature.into()),
            receiver_signature: Some(signed_transaction.receiver_signature.into()),
        }
    }
}
