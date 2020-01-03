// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::impl_hash;
use crate::{
    channel_transaction::ChannelTransaction, channel_transaction_sigs::ChannelTransactionSigs,
};
use anyhow::{ensure, Error, Result};

use libra_crypto::HashValue;
use libra_crypto_derive::CryptoHasher;
use libra_types::account_address::AccountAddress;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::convert::TryFrom;

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, CryptoHasher)]
pub struct SignedChannelTransaction {
    pub raw_tx: ChannelTransaction,
    // use BTree to preserve order.
    pub signatures: BTreeMap<AccountAddress, ChannelTransactionSigs>,
}

impl SignedChannelTransaction {
    pub fn new(
        raw_tx: ChannelTransaction,
        signatures: BTreeMap<AccountAddress, ChannelTransactionSigs>,
    ) -> Self {
        Self { raw_tx, signatures }
    }
}
impl_hash!(SignedChannelTransaction, SignedChannelTransactionHasher);

impl TryFrom<crate::proto::sgtypes::SignedChannelTransaction> for SignedChannelTransaction {
    type Error = Error;

    fn try_from(
        signed_transaction: crate::proto::sgtypes::SignedChannelTransaction,
    ) -> Result<Self> {
        let raw_tx = ChannelTransaction::try_from(signed_transaction.raw_tx.unwrap())?;
        let signers = signed_transaction
            .signers
            .into_iter()
            .map(AccountAddress::try_from)
            .collect::<Result<Vec<_>>>()?;
        let signatures = signed_transaction
            .signatures
            .into_iter()
            .map(ChannelTransactionSigs::try_from)
            .collect::<Result<Vec<_>>>()?;
        ensure!(signers.len() == signatures.len(), "len mismatch.");
        let signatures = signers
            .into_iter()
            .zip(signatures.into_iter())
            .collect::<BTreeMap<_, _>>();
        Ok(SignedChannelTransaction { raw_tx, signatures })
    }
}

impl From<SignedChannelTransaction> for crate::proto::sgtypes::SignedChannelTransaction {
    fn from(signed_transaction: SignedChannelTransaction) -> Self {
        let SignedChannelTransaction { raw_tx, signatures } = signed_transaction;

        let mut signers = Vec::with_capacity(signatures.len());
        let mut signs = Vec::with_capacity(signatures.len());

        for (addr, sig) in signatures.into_iter() {
            signers.push(addr.to_vec());
            signs.push(sig.into());
        }
        Self {
            raw_tx: Some(raw_tx.into()),
            signers,
            signatures: signs,
        }
    }
}
