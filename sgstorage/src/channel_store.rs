// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::channel_transaction_store::ChannelTransactionStore;
use crate::channel_write_set_store::ChannelWriteSetStore;
use crate::ledger_info_store::LedgerStore;
use crate::pending_txn_store::PendingTxnStore;
use crate::schema::participant_public_key_schema::ParticipantPublicKeySchema;
use crate::schema_db::SchemaDB;

use anyhow::{ensure, Result};
use itertools::Itertools;
use libra_crypto::ed25519::Ed25519PublicKey;
use libra_crypto::hash::CryptoHash;
use libra_crypto::HashValue;
use libra_types::account_address::AccountAddress;
use libra_types::channel::{Witness, WitnessData};
use libra_types::transaction::Version;
use libra_types::write_set::WriteSet;
use rocksdb::ReadOptions;
use schemadb::SchemaBatch;
use sgtypes::applied_channel_txn::AppliedChannelTxn;
use sgtypes::channel_transaction_info::ChannelTransactionInfo;
use sgtypes::channel_transaction_to_commit::*;
use sgtypes::ledger_info::LedgerInfo;
use sgtypes::pending_txn::PendingTransaction;
use sgtypes::proof::signed_channel_transaction_proof::SignedChannelTransactionProof;
use sgtypes::signed_channel_transaction_with_proof::SignedChannelTransactionWithProof;
use sgtypes::startup_info::StartupInfo;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Formatter;
use std::ops::Deref;
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub struct ChannelStore<S> {
    db: S,
    ledger_store: LedgerStore<S>,
    transaction_store: ChannelTransactionStore<S>,
    write_set_store: ChannelWriteSetStore<S>,
    pending_txn_store: PendingTxnStore<S>,
    latest_witness: Arc<RwLock<Option<Witness>>>,
    pending_txn: Arc<RwLock<Option<PendingTransaction>>>,
    participant_keys: Arc<RwLock<BTreeMap<AccountAddress, Option<Ed25519PublicKey>>>>,
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
    fn set_witness(&self, write_set: Option<Witness>) {
        let mut write_guard = self.latest_witness.write().expect("should get write lock");
        *write_guard = write_set;
    }

    fn set_pending_txn(&self, pending_txn: Option<PendingTransaction>) {
        let mut write_guard = self.pending_txn.write().expect("should get write lock");
        *write_guard = pending_txn;
    }
}

impl<S> ChannelStore<S>
where
    S: SchemaDB + Clone,
{
    pub fn new(participants: BTreeSet<AccountAddress>, db: S) -> Result<Self> {
        let mut store = ChannelStore {
            db: db.clone(),
            ledger_store: LedgerStore::new(db.clone()),
            transaction_store: ChannelTransactionStore::new(db.clone()),
            write_set_store: ChannelWriteSetStore::new(db.clone()),
            pending_txn_store: PendingTxnStore::new(db.clone()),
            latest_witness: Arc::new(RwLock::new(None)),
            pending_txn: Arc::new(RwLock::new(None)),
            participant_keys: Arc::new(RwLock::new(BTreeMap::new())),
        };
        store.bootstrap(participants)?;
        Ok(store)
    }
    fn bootstrap(&mut self, participants: BTreeSet<AccountAddress>) -> Result<()> {
        self.ledger_store.bootstrap();
        self.load_public_keys()
            .unwrap_or_else(|e| panic!("fail to load public keys {}", e));
        self.load_pending_txn()
            .unwrap_or_else(|e| panic!("fail to load pending txn {}", e));
        self.load_witness()
            .unwrap_or_else(|e| panic!("fail to load witness {}", e));
        if self.participant_keys.read().unwrap().is_empty() {
            let mut sb = SchemaBatch::new();
            for addr in participants {
                sb.put::<ParticipantPublicKeySchema>(&addr, &None).unwrap();
            }
            self.commit(sb)?;
            self.load_public_keys()?;
        }
        Ok(())
    }

    #[inline]
    pub fn db(&self) -> S {
        self.db.clone()
    }

    pub fn pending_txn_store(&self) -> &PendingTxnStore<S> {
        &self.pending_txn_store
    }

    #[cfg(test)]
    pub fn ledger_store(&self) -> &LedgerStore<S> {
        &self.ledger_store
    }
    #[cfg(test)]
    pub fn transaction_store(&self) -> &ChannelTransactionStore<S> {
        &self.transaction_store
    }

    fn load_public_keys(&self) -> Result<()> {
        let mut iter = self
            .db
            .iter::<ParticipantPublicKeySchema>(ReadOptions::default())?;
        let keys = if iter.seek_to_first() {
            iter.fold_results(BTreeMap::new(), |mut a, (addr, pubkey)| {
                a.insert(addr, pubkey);
                a
            })?
        //            iter.collect::<BTreeMap<AccountAddress, Ed25519PublicKey>>()
        } else {
            BTreeMap::default()
        };
        let mut write_guard = self
            .participant_keys
            .write()
            .expect("should get write lock");
        *write_guard = keys;
        Ok(())
    }

    fn load_pending_txn(&self) -> Result<()> {
        let pending_txn_opt = self.pending_txn_store.get_pending_txn()?;
        self.set_pending_txn(pending_txn_opt);
        Ok(())
    }

    fn load_witness(&self) -> Result<()> {
        let witness_option = match self.ledger_store.get_latest_ledger_info_option() {
            None => None,
            Some(ledger_info) => {
                let version = ledger_info.version();
                let ws = self.write_set_store.get_write_set_by_version(version)?;
                let txn = self.transaction_store.get_transaction(version)?;
                let witness = generate_witness(&txn, ws);
                Some(witness)
            }
        };
        self.set_witness(witness_option);
        Ok(())
    }
}

fn generate_witness(txn: &AppliedChannelTxn, write_set: WriteSet) -> Witness {
    let witness_signatures = match txn {
        AppliedChannelTxn::Offchain(t) => t
            .signatures
            .values()
            .map(|s| s.witness_data_signature.clone())
            .collect(),
        _ => vec![],
    };

    let witness = Witness::new(
        WitnessData::new(txn.channel_sequence_number() + 1, write_set),
        witness_signatures,
    );

    witness
}

/// Write data part
impl<S> ChannelStore<S>
where
    S: SchemaDB,
{
    pub fn save_tx(
        &self,
        txn_to_commit: ChannelTransactionToCommit,
        version: Version,
        ledger_info: &Option<LedgerInfo>,
        clear_pending_txn: bool,
    ) -> Result<()> {
        if let Some(x) = ledger_info {
            let claimed_last_version = x.version();
            ensure!(
                claimed_last_version == version,
                "Transaction batch not applicable: version {}, last_version {}",
                version,
                claimed_last_version,
            );
        }

        let witness = generate_witness(
            txn_to_commit.transaction(),
            txn_to_commit.write_set().clone(),
        );
        // get write batch
        let mut schema_batch = SchemaBatch::default();
        let mut updated_public_keys = BTreeMap::new();
        {
            let read_guard = self.participant_keys.read().unwrap();
            for ((addr, old_key), new_key) in read_guard
                .iter()
                .zip(txn_to_commit.transaction().participant_keys())
            {
                match old_key {
                    Some(o) if o == &new_key => {}
                    _ => {
                        let new_key = Some(new_key);
                        schema_batch.put::<ParticipantPublicKeySchema>(addr, &new_key)?;
                        updated_public_keys.insert(addr.clone(), new_key);
                    }
                }
            }
        }

        let new_ledger_hash = self.save_tx_impl(txn_to_commit, version, &mut schema_batch)?;

        if let Some(x) = ledger_info {
            let expected_root_hash = x.transaction_accumulator_hash();
            ensure!(
                new_ledger_hash == expected_root_hash,
                "Root hash calculated doesn't match expected. {:?} vs {:?}",
                new_ledger_hash,
                expected_root_hash,
            );
            self.ledger_store.put_ledger_info(x, &mut schema_batch)?;
        }

        if clear_pending_txn {
            self.pending_txn_store.clear(&mut schema_batch)?;
        }

        self.commit(schema_batch)?;

        // Once everything is successfully persisted, update the latest in-memory ledger info.
        if let Some(x) = ledger_info {
            self.ledger_store.set_latest_ledger_info(x.clone());
        }

        // update public_keys cache.
        let mut write_guard = self.participant_keys.write().unwrap();
        write_guard.append(&mut updated_public_keys);

        // and cache the write set
        self.set_witness(Some(witness));
        if clear_pending_txn {
            self.set_pending_txn(None);
        }
        // TODO: wake pruner
        Ok(())
    }

    pub fn save_pending_txn(
        &mut self,
        pending_txn: PendingTransaction,
        persist: bool,
    ) -> Result<()> {
        if persist {
            let mut sb = SchemaBatch::new();
            self.pending_txn_store
                .save_pending_txn(&pending_txn, &mut sb)?;
            self.commit(sb)?;
        }

        self.set_pending_txn(Some(pending_txn));
        Ok(())
    }

    /// clean pending txn as it never exists.
    pub fn clear_pending_txn(&self) -> Result<()> {
        let mut sb = SchemaBatch::new();
        self.pending_txn_store.clear(&mut sb)?;
        self.commit(sb)?;
        self.set_pending_txn(None);
        Ok(())
    }

    fn save_tx_impl(
        &self,
        tx: ChannelTransactionToCommit,
        version: Version,
        mut schema_batch: &mut SchemaBatch,
    ) -> Result<HashValue> {
        let ChannelTransactionToCommit {
            signed_channel_txn: signed_txn,
            write_set,
            major_status,
            gas_used,
            ..
        } = tx;
        // TODO: save write set
        let write_set_root_hash =
            self.write_set_store
                .put_write_set(version, write_set, &mut schema_batch)?;
        // TODO: save events
        //        let events_root_hash = self
        //            .event_store
        //            .put_events(version, _events, &mut schema_batch)?;

        let tx_hash: HashValue = signed_txn.hash();
        let travel = signed_txn.travel();
        self.transaction_store
            .put_transaction(version, signed_txn, &mut schema_batch)?;

        let tx_info = ChannelTransactionInfo::new(
            tx_hash,
            write_set_root_hash,
            HashValue::default(),
            major_status,
            travel,
            gas_used,
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
    S: SchemaDB,
{
    /// Gets information needed from storage during the startup of the executor or state
    /// synchronizer module.
    pub fn get_startup_info(&self) -> Result<Option<StartupInfo>> {
        // Get the latest ledger info. Return None if not bootstrapped.
        let ledger_info = match self.ledger_store.get_latest_ledger_info_option() {
            Some(x) => x,
            None => return Ok(None),
        };

        let (latest_version, _txn_info) = self.ledger_store.get_latest_transaction_info()?;

        let ledger_frozen_subtree_hashes = self
            .ledger_store
            .get_ledger_frozen_subtree_hashes(latest_version)?;

        Ok(Some(StartupInfo {
            ledger_info,
            latest_version,
            ledger_frozen_subtree_hashes,
        }))
    }

    pub fn get_write_set_by_version(&self, version: u64) -> Result<WriteSet> {
        self.write_set_store.get_write_set_by_version(version)
    }

    pub fn get_pending_txn(&self) -> Option<PendingTransaction> {
        self.pending_txn
            .read()
            .expect("should get read lock")
            .deref()
            .clone()
    }

    pub fn get_latest_witness(&self) -> Option<Witness> {
        self.latest_witness
            .read()
            .expect("should get read lock")
            .deref()
            .clone()
    }

    pub fn get_participant_keys(&self) -> BTreeMap<AccountAddress, Ed25519PublicKey> {
        self.participant_keys
            .read()
            .unwrap()
            .iter()
            .filter_map(|(k, v)| match v {
                Some(v) => Some((k.clone(), v.clone())),
                None => None,
            })
            .collect()
    }

    pub fn get_transaction_by_channel_seq_number(
        &self,
        channel_sequence_number: u64,
        fetch_events: bool,
    ) -> Result<SignedChannelTransactionWithProof> {
        // Get the latest ledger info and signatures
        let ledger_info = self.ledger_store.get_latest_ledger_info()?;
        let ledger_version = ledger_info.version();
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

    // Gets the latest version number available in the ledger.
    //    fn get_latest_version(&self) -> Result<Version> {
    //        Ok(self
    //            .ledger_store
    //            .get_latest_ledger_info()?
    //            .ledger_info()
    //            .version())
    //    }
}
