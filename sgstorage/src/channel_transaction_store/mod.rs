// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) The SG Core Contributors

//! This file defines transaction store APIs that are related to committed signed transactions.

use crate::error::SgStorageError;
use crate::schema::{
    channel_transaction::{ChannelTransactionSchema, ChannelTransactionVersion},
    channel_transaction_by_account::ChannelTransactionByAccountSchema,
};
use crate::SgDB;
use failure::prelude::*;
use libra_types::transaction::SignedTransaction;
use libra_types::{
    account_address::AccountAddress,
    transaction::{Transaction, TransactionPayload, Version},
};
use schemadb::SchemaBatch;
use std::sync::Arc;

pub struct ChannelTransactionStore {
    db: Arc<SgDB>,
    receiver: AccountAddress,
}

impl ChannelTransactionStore {
    pub fn new(db: Arc<SgDB>, receiver: AccountAddress) -> Self {
        Self { db, receiver }
    }

    /// Gets the version of a transaction by the `tx_sender_address` and `channel_sequence_number`.
    pub fn lookup_transaction_by_account(
        &self,
        tx_sender_address: AccountAddress,
        channel_sequence_number: u64,
        ledger_version: Version,
    ) -> Result<Option<Version>> {
        let lookup_key = (self.receiver, tx_sender_address, channel_sequence_number);
        if let Some(version) = self
            .db
            .get::<ChannelTransactionByAccountSchema>(&lookup_key)?
        {
            if version <= ledger_version {
                return Ok(Some(version));
            }
        }

        Ok(None)
    }

    /// Get signed transaction given `version`
    pub fn get_transaction(&self, version: Version) -> Result<SignedTransaction> {
        let key = ChannelTransactionVersion(self.receiver, version);
        let txn = self
            .db
            .get::<ChannelTransactionSchema>(&key)?
            .ok_or_else(|| SgStorageError::NotFound(format!("Txn {}", version)))?;

        match txn {
            Transaction::UserTransaction(user_txn) => Ok(user_txn),
            // TODO: support other variants after API change
            _ => unreachable!("Currently only supports user transactions."),
        }
    }

    /// Save signed transaction at `version`
    pub fn put_transaction(
        &self,
        version: Version,
        transaction: &Transaction,
        cs: &mut SchemaBatch,
    ) -> Result<()> {
        if let Transaction::UserTransaction(txn) = transaction {
            let channel_seq_number = match txn.raw_txn().payload() {
                TransactionPayload::ChannelScript(csp) => csp.channel_sequence_number,
                TransactionPayload::ChannelWriteSet(cwp) => cwp.channel_sequence_number,
                _ => bail!("only support channel transaction"),
            };
            cs.put::<ChannelTransactionByAccountSchema>(
                &(self.receiver, txn.sender(), channel_seq_number),
                &version,
            )?;
        }

        let channel_transaction_version = ChannelTransactionVersion(self.receiver, version);
        cs.put::<ChannelTransactionSchema>(&channel_transaction_version, &transaction)?;

        Ok(())
    }
}

//
//#[cfg(test)]
//mod test;
