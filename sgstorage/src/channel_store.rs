// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::channel_db::ChannelAddressProvider;
use crate::channel_state_store::ChannelStateStore;
use crate::channel_transaction_store::ChannelTransactionStore;
use crate::channel_write_set_store::ChannelWriteSetStore;
use crate::ledger_info_store::LedgerStore;
use crate::schema_db::SchemaDB;

use crypto::hash::CryptoHash;
use crypto::HashValue;
use failure::prelude::*;
use libra_types::account_address::AccountAddress;
use libra_types::account_state_blob::AccountStateBlob;
use libra_types::crypto_proxies::LedgerInfoWithSignatures;
use libra_types::proof::SparseMerkleProof;
use libra_types::transaction::Version;
use libra_types::write_set::WriteSet;

use schemadb::SchemaBatch;
use sgtypes::channel_transaction_info::ChannelTransactionInfo;
use sgtypes::channel_transaction_to_commit::*;
use sgtypes::proof::signed_channel_transaction_proof::SignedChannelTransactionProof;
use sgtypes::signed_channel_transaction_with_proof::SignedChannelTransactionWithProof;
use std::fmt::Formatter;
use std::ops::Deref;
use std::sync::{Arc, RwLock};
use storage_proto::StartupInfo;

#[derive(Clone)]
pub struct ChannelStore<S> {
    db: S,
    state_store: ChannelStateStore<S>,
    ledger_store: LedgerStore<S>,
    transaction_store: ChannelTransactionStore<S>,
    write_set_store: ChannelWriteSetStore<S>,
    latest_write_set: Arc<RwLock<Option<WriteSet>>>,
}

impl<S> core::fmt::Debug for ChannelStore<S>
where
    S: core::fmt::Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "db: {:?}", self.db)
    }
}

impl<S> ChannelStore<S> {
    fn set_write_set(&self, write_set: Option<WriteSet>) -> Result<()> {
        let mut write_guard = self
            .latest_write_set
            .try_write()
            .map_err(|_| format_err!("try to get write lock error"))?;
        *write_guard = write_set;
        Ok(())
    }
}

impl<S> ChannelStore<S>
where
    S: SchemaDB + Clone,
{
    pub fn new(db: S) -> Self {
        let store = ChannelStore {
            db: db.clone(),
            state_store: ChannelStateStore::new(db.clone()),
            ledger_store: LedgerStore::new(db.clone()),
            transaction_store: ChannelTransactionStore::new(db.clone()),
            write_set_store: ChannelWriteSetStore::new(db.clone()),
            latest_write_set: Arc::new(RwLock::new(None)),
        };

        // TODO refactor this
        store.ledger_store.bootstrap();
        let write_set_option = match store.ledger_store.get_latest_ledger_info_option() {
            None => None,
            Some(ledger_info) => {
                let version = ledger_info.ledger_info().version();
                let ws = store
                    .write_set_store
                    .get_write_set_by_version(version)
                    .expect("read lastest writeset from db shold work");
                Some(ws)
            }
        };
        store
            .set_write_set(write_set_option)
            .expect("set write set should be ok");
        store
    }

    #[inline]
    pub fn db(&self) -> S {
        self.db.clone()
    }
    #[cfg(test)]
    pub fn state_store(&self) -> &ChannelStateStore<S> {
        &self.state_store
    }
    #[cfg(test)]
    pub fn ledger_store(&self) -> &LedgerStore<S> {
        &self.ledger_store
    }
    #[cfg(test)]
    pub fn transaction_store(&self) -> &ChannelTransactionStore<S> {
        &self.transaction_store
    }
}

/// Write data part
impl<S> ChannelStore<S>
where
    S: SchemaDB + ChannelAddressProvider,
{
    pub fn save_tx(
        &self,
        txn_to_commit: ChannelTransactionToCommit,
        version: Version,
        ledger_info_with_sigs: &Option<LedgerInfoWithSignatures>,
    ) -> Result<()> {
        if let Some(x) = ledger_info_with_sigs {
            let claimed_last_version = x.ledger_info().version();
            ensure!(
                claimed_last_version == version,
                "Transaction batch not applicable: version {}, last_version {}",
                version,
                claimed_last_version,
            );
        }
        let write_set = txn_to_commit.write_set().clone();

        // get write batch
        let mut schema_batch = SchemaBatch::default();
        let new_ledger_hash = self.save_tx_impl(txn_to_commit, version, &mut schema_batch)?;

        if let Some(x) = ledger_info_with_sigs {
            let expected_root_hash = x.ledger_info().transaction_accumulator_hash();
            ensure!(
                new_ledger_hash == expected_root_hash,
                "Root hash calculated doesn't match expected. {:?} vs {:?}",
                new_ledger_hash,
                expected_root_hash,
            );
            self.ledger_store.put_ledger_info(x, &mut schema_batch)?;
        }

        self.commit(schema_batch)?;

        // Once everything is successfully persisted, update the latest in-memory ledger info.
        if let Some(x) = ledger_info_with_sigs {
            self.ledger_store.set_latest_ledger_info(x.clone());
        }
        // and cache the write set
        self.set_write_set(Some(write_set))?;
        // TODO: wake pruner
        Ok(())
    }

    fn save_tx_impl(
        &self,
        tx: ChannelTransactionToCommit,
        version: Version,
        mut schema_batch: &mut SchemaBatch,
    ) -> Result<HashValue> {
        let (signed_txn, write_set, witness_states, _events, major_status) = tx.into();
        let state_root_hash =
            self.state_store
                .put_channel_state_set(witness_states, version, &mut schema_batch)?;
        // TODO: save write set
        let write_set_root_hash =
            self.write_set_store
                .put_write_set(version, write_set, &mut schema_batch)?;
        // TODO: save events
        //        let events_root_hash = self
        //            .event_store
        //            .put_events(version, _events, &mut schema_batch)?;

        let tx_hash: HashValue = signed_txn.hash();
        self.transaction_store
            .put_transaction(version, signed_txn, &mut schema_batch)?;

        let tx_info = ChannelTransactionInfo::new(
            tx_hash,
            write_set_root_hash,
            state_root_hash,
            HashValue::default(),
            major_status,
        );
        // TODO: save to ledger store
        let new_ledger_root_hash =
            self.ledger_store
                .put_tx_info(version, tx_info, &mut schema_batch)?;
        Ok(new_ledger_root_hash)
    }

    /// persist the batch into storage
    fn commit(&self, schema_batch: SchemaBatch) -> Result<()> {
        self.db.write_schemas(schema_batch)?;

        Ok(())
    }
}

impl<S> ChannelStore<S>
where
    S: SchemaDB + ChannelAddressProvider,
{
    /// Gets information needed from storage during the startup of the executor or state
    /// synchronizer module.
    pub fn get_startup_info(&self) -> Result<Option<StartupInfo>> {
        // Get the latest ledger info. Return None if not bootstrapped.
        let ledger_info_with_sigs = match self.ledger_store.get_latest_ledger_info_option() {
            Some(x) => x,
            None => return Ok(None),
        };
        let ledger_info = ledger_info_with_sigs.ledger_info().clone();

        let (latest_version, txn_info) = self.ledger_store.get_latest_transaction_info()?;

        let account_state_root_hash = txn_info.state_root_hash();

        let ledger_frozen_subtree_hashes = self
            .ledger_store
            .get_ledger_frozen_subtree_hashes(latest_version)?;

        Ok(Some(StartupInfo {
            ledger_info,
            latest_version,
            account_state_root_hash,
            ledger_frozen_subtree_hashes,
        }))
    }

    pub fn get_write_set_by_version(&self, version: u64) -> Result<WriteSet> {
        self.write_set_store.get_write_set_by_version(version)
    }

    pub fn get_latest_write_set(&self) -> Option<WriteSet> {
        self.latest_write_set
            .read()
            .expect("should get read lock")
            .deref()
            .clone()
    }

    pub fn get_transaction_by_channel_seq_number(
        &self,
        channel_sequence_number: u64,
        fetch_events: bool,
    ) -> Result<SignedChannelTransactionWithProof> {
        // Get the latest ledger info and signatures
        let ledger_info_with_sigs = self.ledger_store.get_latest_ledger_info()?;
        let ledger_version = ledger_info_with_sigs.ledger_info().version();
        self.get_txn_with_proof(channel_sequence_number, ledger_version, fetch_events)
    }

    fn get_txn_with_proof(
        &self,
        version: u64,
        ledger_version: u64,
        fetch_events: bool,
    ) -> Result<SignedChannelTransactionWithProof> {
        let (txn_info, txn_info_accumulator_proof) = self
            .ledger_store
            .get_transaction_info_with_proof(version, ledger_version)?;
        let proof = SignedChannelTransactionProof::new(txn_info_accumulator_proof, txn_info);
        let signed_transaction = self.transaction_store.get_transaction(version)?;
        // TODO(caojiafeng): impl me
        let events = if fetch_events { None } else { None };

        Ok(SignedChannelTransactionWithProof {
            version,
            signed_transaction,
            events,
            proof,
        })
    }

    //    /// Returns the account state corresponding to the given version and account address with proof
    //    /// based on `ledger_version`
    //    pub fn get_account_state_with_proof(
    //        &self,
    //        address: AccountAddress,
    //        version: Version,
    //        ledger_version: Version,
    //    ) -> Result<AccountStateWithProof> {
    //        ensure!(
    //            version <= ledger_version,
    //            "The queried version {} should be equal to or older than ledger version {}.",
    //            version,
    //            ledger_version
    //        );
    //        let latest_version = self.get_latest_version()?;
    //        ensure!(
    //            ledger_version <= latest_version,
    //            "The ledger version {} is greater than the latest version currently in ledger: {}",
    //            ledger_version,
    //            latest_version
    //        );
    //
    //        let (txn_info, txn_info_accumulator_proof) = self
    //            .ledger_store
    //            .get_transaction_info_with_proof(version, ledger_version)?;
    //        let (account_state_blob, sparse_merkle_proof) = self
    //            .state_store
    //            .get_account_state_with_proof_by_version(address, version)?;
    //        Ok(AccountStateWithProof::new(
    //            version,
    //            account_state_blob,
    //            AccountStateProof::new(txn_info_accumulator_proof, txn_info, sparse_merkle_proof),
    //        ))
    //    }
    //

    /// Gets an account state by account address, out of the ledger state indicated by the state
    /// Merkle tree root hash.
    ///
    /// This is used by tx applier internally.
    pub fn get_account_state_with_proof_by_version(
        &self,
        address: AccountAddress,
        version: Version,
    ) -> Result<(Option<AccountStateBlob>, SparseMerkleProof)> {
        self.state_store
            .get_account_state_with_proof_by_version(address, version)
    }

    // Gets the latest version number available in the ledger.
    //    fn get_latest_version(&self) -> Result<Version> {
    //        Ok(self
    //            .ledger_store
    //            .get_latest_ledger_info()?
    //            .ledger_info()
    //            .version())
    //    }
}
