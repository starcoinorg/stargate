// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This file defines transaction store APIs that are related to committed signed transactions.

use crate::error::SgStorageError;
use crate::schema::channel_transaction_schema::*;
use crate::schema_db::SchemaDB;
use failure::prelude::*;
use libra_types::{account_address::AccountAddress, transaction::Version};
use libradb::schema::transaction_by_account::*;
use schemadb::SchemaBatch;
use sgtypes::signed_channel_transaction::SignedChannelTransaction;

#[derive(Clone)]
pub struct ChannelTransactionStore<S> {
    db: S,
}

impl<S> ChannelTransactionStore<S> {
    pub fn new(db: S) -> Self {
        Self { db }
    }
}

impl<S> ChannelTransactionStore<S>
where
    S: SchemaDB,
{
    /// Gets the version of a transaction by the `tx_sender_address` and `channel_sequence_number`.
    pub fn lookup_transaction_by_account(
        &self,
        tx_sender_address: AccountAddress,
        channel_sequence_number: u64,
        ledger_version: Version,
    ) -> Result<Option<Version>> {
        let lookup_key = (tx_sender_address, channel_sequence_number);
        if let Some(version) = self.db.get::<TransactionByAccountSchema>(&lookup_key)? {
            if version <= ledger_version {
                return Ok(Some(version));
            }
        }

        Ok(None)
    }

    /// Get signed transaction given `version`
    pub fn get_transaction(&self, version: Version) -> Result<SignedChannelTransaction> {
        let txn = self
            .db
            .get::<SignedChannelTransactionSchema>(&version)?
            .ok_or_else(|| SgStorageError::NotFound(format!("Txn {}", version)))?;

        Ok(txn)
    }

    /// Save signed transaction at `version`
    pub fn put_transaction(
        &self,
        version: Version,
        transaction: SignedChannelTransaction,
        cs: &mut SchemaBatch,
    ) -> Result<()> {
        let channel_seq_number = transaction.raw_tx.channel_sequence_number();
        let proposer = transaction.raw_tx.proposer();
        cs.put::<TransactionByAccountSchema>(&(proposer, channel_seq_number), &version)?;

        cs.put::<SignedChannelTransactionSchema>(&version, &transaction)?;

        Ok(())
    }
}
