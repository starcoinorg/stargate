// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::schema::pending_transaction_schema::PendingTransactionSchema;
use crate::schema_db::SchemaDB;
use failure::prelude::*;
use schemadb::SchemaBatch;
use sgtypes::pending_txn::PendingTransaction;
#[derive(Debug, Clone)]
pub struct PendingTxnStore<S> {
    db: S,
}

impl<S> PendingTxnStore<S> {
    pub fn new(db: S) -> Self {
        Self { db }
    }
}

impl<S> PendingTxnStore<S>
where
    S: SchemaDB,
{
    const PENDING_TXN_KEY: &'static str = "pending";
    pub fn get_pending_txn(&self) -> Result<Option<PendingTransaction>> {
        self.db
            .get::<PendingTransactionSchema>(&Self::PENDING_TXN_KEY.to_string())
    }
    pub fn clear(&self, write_batch: &mut SchemaBatch) -> Result<()> {
        write_batch.delete::<PendingTransactionSchema>(&Self::PENDING_TXN_KEY.to_string())
    }
    pub fn save_pending_txn(
        &self,
        pending_txn: &PendingTransaction,
        write_batch: &mut SchemaBatch,
    ) -> Result<()> {
        write_batch.put::<PendingTransactionSchema>(&Self::PENDING_TXN_KEY.to_string(), pending_txn)
    }
}
