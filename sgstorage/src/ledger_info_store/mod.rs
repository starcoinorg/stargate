// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This file defines ledger store APIs that are related to the main ledger accumulator, from the
//! root(LedgerInfo) to leaf(TransactionInfo).

use crate::error::SgStorageError;
use crate::schema_db::SchemaDB;
use accumulator::{HashReader, MerkleAccumulator};
use arc_swap::ArcSwap;
use crypto::{
    hash::{CryptoHash, TransactionAccumulatorHasher},
    HashValue,
};
use failure::prelude::*;
use libra_types::crypto_proxies::LedgerInfoWithSignatures;
use libra_types::proof::position::Position;
use libra_types::proof::{AccumulatorConsistencyProof, TransactionAccumulatorProof};
use libra_types::transaction::{TransactionInfo, Version};
use libradb::schema::{ledger_info::*, transaction_accumulator::*, transaction_info::*};
use schemadb::{ReadOptions, SchemaBatch};
use std::{ops::Deref, sync::Arc};

pub struct LedgerStore<S> {
    db: Arc<S>,
    latest_ledger_info: ArcSwap<Option<LedgerInfoWithSignatures>>,
}

impl<S> LedgerStore<S> {
    pub fn new(db: Arc<S>) -> Self {
        Self {
            db,
            latest_ledger_info: ArcSwap::from(Arc::new(None)),
        }
    }
}

impl<S> LedgerStore<S>
where
    S: SchemaDB,
{
    /// Return the ledger infos with their least 2f+1 signatures starting from `start_epoch` to
    /// the most recent one.
    /// Note: ledger infos and signatures are only available at the last version of each earlier
    /// epoch and at the latest version of current epoch.
    pub fn get_latest_ledger_infos_per_epoch(
        &self,
        start_epoch: u64,
    ) -> Result<Vec<LedgerInfoWithSignatures>> {
        let mut iter = self.db.iter::<LedgerInfoSchema>(ReadOptions::default())?;
        iter.seek(&start_epoch)?;
        Ok(iter.map(|kv| Ok(kv?.1)).collect::<Result<Vec<_>>>()?)
    }

    pub fn get_latest_ledger_info_option(&self) -> Option<LedgerInfoWithSignatures> {
        let ledger_info_ptr = self.latest_ledger_info.load();
        let ledger_info: &Option<_> = ledger_info_ptr.deref();
        ledger_info.clone()
    }

    pub fn get_latest_ledger_info(&self) -> Result<LedgerInfoWithSignatures> {
        self.get_latest_ledger_info_option()
            .ok_or_else(|| SgStorageError::NotFound(String::from("Genesis LedgerInfo")).into())
    }

    pub fn set_latest_ledger_info(&self, ledger_info_with_sigs: LedgerInfoWithSignatures) {
        self.latest_ledger_info
            .store(Arc::new(Some(ledger_info_with_sigs)));
    }

    /// Get transaction info given `version`
    pub fn get_transaction_info(&self, version: Version) -> Result<TransactionInfo> {
        self.db
            .get::<TransactionInfoSchema>(&version)?
            .ok_or_else(|| format_err!("No TransactionInfo at version {}", version))
    }

    pub fn get_latest_transaction_info_option(&self) -> Result<Option<(Version, TransactionInfo)>> {
        let mut iter = self
            .db
            .iter::<TransactionInfoSchema>(ReadOptions::default())?;
        iter.seek_to_last();
        iter.next().transpose()
    }

    /// Get latest transaction info together with its version. Note that during node syncing, this
    /// version can be greater than what's in the latest LedgerInfo.
    pub fn get_latest_transaction_info(&self) -> Result<(Version, TransactionInfo)> {
        self.get_latest_transaction_info_option()?.ok_or_else(|| {
            SgStorageError::NotFound(String::from("Genesis TransactionInfo.")).into()
        })
    }

    /// Get transaction info at `version` with proof towards root of ledger at `ledger_version`.
    pub fn get_transaction_info_with_proof(
        &self,
        version: Version,
        ledger_version: Version,
    ) -> Result<(TransactionInfo, TransactionAccumulatorProof)> {
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
    ) -> Result<TransactionAccumulatorProof> {
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
        tx_info: &TransactionInfo,
        batch: &mut SchemaBatch,
    ) -> Result<HashValue> {
        batch.put::<TransactionInfoSchema>(&version, tx_info)?;

        let tx_info_hash = tx_info.hash();
        let (root_hash, writes) = Accumulator::append(self, version, &[tx_info_hash])?;

        for (pos, hash) in writes.iter() {
            batch.put::<TransactionAccumulatorSchema>(pos, hash)?;
        }

        Ok(root_hash)
    }

    /// Write `ledger_info` to `cs`.
    pub fn put_ledger_info(
        &self,
        ledger_info_with_sigs: &LedgerInfoWithSignatures,
        cs: &mut SchemaBatch,
    ) -> Result<()> {
        cs.put::<LedgerInfoSchema>(
            &ledger_info_with_sigs.ledger_info().epoch_num(),
            ledger_info_with_sigs,
        )
    }
}

type Accumulator<T> = MerkleAccumulator<LedgerStore<T>, TransactionAccumulatorHasher>;

impl<S> HashReader for LedgerStore<S>
where
    S: SchemaDB,
{
    fn get(&self, position: Position) -> Result<HashValue> {
        self.db
            .get::<TransactionAccumulatorSchema>(&position)?
            .ok_or_else(|| format_err!("{} does not exist.", position))
    }
}
