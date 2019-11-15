// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This file defines ledger store APIs that are related to the main ledger accumulator, from the
//! root(LedgerInfo) to leaf(TransactionInfo).

use crate::error::SgStorageError;
use crate::schema::channel_transaction_info::*;
use crate::schema::{channel_transaction_accumulator::*, ledger_info_schema::*};
use crate::schema_db::SchemaDB;
use accumulator::{HashReader, MerkleAccumulator};
use failure::prelude::*;
use libra_crypto::{hash::CryptoHash, HashValue};
use libra_types::proof::position::Position;
use libra_types::proof::AccumulatorConsistencyProof;
use libra_types::transaction::Version;
use schemadb::{ReadOptions, SchemaBatch};
use sgtypes::ledger_info::LedgerInfo;
use sgtypes::{
    channel_transaction_info::ChannelTransactionInfo, hash::ChannelTransactionAccumulatorHasher,
    proof::ChannelTransactionAccumulatorProof,
};
use std::fmt::Formatter;
use std::sync::Arc;
use std::sync::RwLock;

#[derive(Clone)]
pub struct LedgerStore<S> {
    db: S,
    latest_ledger_info: Arc<RwLock<Option<LedgerInfo>>>,
}
impl<S> core::fmt::Debug for LedgerStore<S>
where
    S: core::fmt::Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "db: {:?}, latest_ledger_info: {:?}",
            self.db, self.latest_ledger_info
        )
    }
}

impl<S> LedgerStore<S> {
    pub fn new(db: S) -> Self {
        Self {
            db,
            latest_ledger_info: Arc::new(RwLock::new(None)),
        }
    }
}

impl<S> LedgerStore<S>
where
    S: SchemaDB,
{
    // Upon restart, read the latest ledger info and signatures and cache them in memory.
    pub fn bootstrap(&self) {
        let ledger_info = {
            let mut iter = self
                .db
                .iter::<LedgerInfoSchema>(ReadOptions::default())
                .expect("Constructing iterator should work.");
            iter.seek_to_last();
            iter.next()
                .transpose()
                .expect("Reading latest ledger info from DB should work.")
                .map(|kv| kv.1)
        };
        if let Some(ledger_info) = ledger_info {
            self.set_latest_ledger_info(ledger_info);
        }
    }

    /// Return the ledger infos starting from `start_epoch` to
    /// the most recent one.
    /// Note: ledger infos and signatures are only available at the last version of each earlier
    /// epoch and at the latest version of current epoch.
    pub fn get_latest_ledger_infos_per_epoch(&self, start_epoch: u64) -> Result<Vec<LedgerInfo>> {
        let mut iter = self.db.iter::<LedgerInfoSchema>(ReadOptions::default())?;
        iter.seek(&start_epoch)?;
        Ok(iter.map(|kv| Ok(kv?.1)).collect::<Result<Vec<_>>>()?)
    }

    pub fn get_latest_ledger_info_option(&self) -> Option<LedgerInfo> {
        let ledger_info_ptr = self.latest_ledger_info.read().unwrap();
        (*ledger_info_ptr).clone()
    }

    pub fn get_latest_ledger_info(&self) -> Result<LedgerInfo> {
        self.get_latest_ledger_info_option()
            .ok_or_else(|| SgStorageError::NotFound(String::from("Genesis LedgerInfo")).into())
    }

    pub fn set_latest_ledger_info(&self, ledger_info_with_sigs: LedgerInfo) {
        *self.latest_ledger_info.write().unwrap() = Some(ledger_info_with_sigs);
    }

    /// Get transaction info given `version`
    pub fn get_transaction_info(&self, version: Version) -> Result<ChannelTransactionInfo> {
        self.db
            .get::<ChannelTransactionInfoSchema>(&version)?
            .ok_or_else(|| format_err!("No TransactionInfo at version {}", version))
    }

    pub fn get_latest_transaction_info_option(
        &self,
    ) -> Result<Option<(Version, ChannelTransactionInfo)>> {
        let mut iter = self
            .db
            .iter::<ChannelTransactionInfoSchema>(ReadOptions::default())?;
        iter.seek_to_last();
        iter.next().transpose()
    }

    /// Get latest transaction info together with its version. Note that during node syncing, this
    /// version can be greater than what's in the latest LedgerInfo.
    pub fn get_latest_transaction_info(&self) -> Result<(Version, ChannelTransactionInfo)> {
        self.get_latest_transaction_info_option()?.ok_or_else(|| {
            SgStorageError::NotFound(String::from("Genesis TransactionInfo.")).into()
        })
    }

    /// Get transaction info at `version` with proof towards root of ledger at `ledger_version`.
    pub fn get_transaction_info_with_proof(
        &self,
        version: Version,
        ledger_version: Version,
    ) -> Result<(ChannelTransactionInfo, ChannelTransactionAccumulatorProof)> {
        Ok((
            self.get_transaction_info(version)?,
            self.get_transaction_proof(version, ledger_version)?,
        ))
    }

    /// Get proof for transaction at `version` towards root of ledger at `ledger_version`.
    pub fn get_transaction_proof(
        &self,
        version: Version,
        ledger_version: Version,
    ) -> Result<ChannelTransactionAccumulatorProof> {
        Accumulator::get_proof(self, ledger_version + 1 /* num_leaves */, version)
    }

    /// Gets proof that shows the ledger at `ledger_version` is consistent with the ledger at
    /// `client_known_version`.
    pub fn get_consistency_proof(
        &self,
        client_known_version: Version,
        ledger_version: Version,
    ) -> Result<AccumulatorConsistencyProof> {
        Accumulator::get_consistency_proof(self, ledger_version + 1, client_known_version + 1)
    }
    /// From left to right, get frozen subtree root hashes of the transaction accumulator.
    pub fn get_ledger_frozen_subtree_hashes(&self, version: Version) -> Result<Vec<HashValue>> {
        Accumulator::get_frozen_subtree_hashes(self, version + 1)
    }

    /// Write `txn_info` to `batch`. Assigned `version` to the the version number of the
    /// transaction.
    pub fn put_tx_info(
        &self,
        version: Version,
        tx_info: ChannelTransactionInfo,
        batch: &mut SchemaBatch,
    ) -> Result<HashValue> {
        let tx_info_hash = tx_info.hash();
        let (root_hash, writes) = Accumulator::append(self, version, &[tx_info_hash])?;

        batch.put::<ChannelTransactionInfoSchema>(&version, &tx_info)?;
        for (pos, hash) in writes.iter() {
            batch.put::<ChannelTransactionAccumulatorSchema>(pos, hash)?;
        }

        Ok(root_hash)
    }

    /// Write `ledger_info` to `cs`.
    pub fn put_ledger_info(&self, ledger_info: &LedgerInfo, cs: &mut SchemaBatch) -> Result<()> {
        cs.put::<LedgerInfoSchema>(&ledger_info.epoch(), ledger_info)
    }
}

type Accumulator<T> = MerkleAccumulator<LedgerStore<T>, ChannelTransactionAccumulatorHasher>;

impl<S> HashReader for LedgerStore<S>
where
    S: SchemaDB,
{
    fn get(&self, position: Position) -> Result<HashValue> {
        self.db
            .get::<ChannelTransactionAccumulatorSchema>(&position)?
            .ok_or_else(|| format_err!("{} does not exist.", position))
    }
}
