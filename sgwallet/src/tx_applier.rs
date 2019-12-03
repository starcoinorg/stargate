// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use failure::prelude::*;
use itertools::Itertools;
use libra_crypto::hash::{
    CryptoHash, EventAccumulatorHasher, HashValue, SPARSE_MERKLE_PLACEHOLDER_HASH,
};
use libra_logger::prelude::*;
use libra_types::account_address::AccountAddress;
use libra_types::account_state_blob::AccountStateBlob;
use libra_types::proof::accumulator::InMemoryAccumulator;
use libra_types::proof::SparseMerkleProof;
use libra_types::transaction::Version;
use libra_types::write_set::WriteSet;
use scratchpad::{ProofRead, SparseMerkleTree};
use sgstorage::channel_db::{ChannelAddressProvider, ChannelDB};
use sgstorage::channel_store::ChannelStore;
use sgtypes::channel_transaction_info::ChannelTransactionInfo;
use sgtypes::channel_transaction_to_commit::{
    ChannelTransactionToApply, ChannelTransactionToCommit,
};
use sgtypes::hash::*;
use sgtypes::ledger_info::LedgerInfo;
use sgtypes::write_set_item::WriteSetItem;
use std::collections::{BTreeMap, HashMap};
use std::convert::{TryFrom, TryInto};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// channel's account states and proof in offchain.
#[derive(Debug)]
pub struct AppliedStateCache {
    account_to_btree_cache: HashMap<AccountAddress, BTreeMap<Vec<u8>, Vec<u8>>>,
    account_to_proof_cache: HashMap<HashValue, SparseMerkleProof>,
}

#[derive(Debug)]
pub struct AppliedTrees {
    epoch: u64,
    state_tree: SparseMerkleTree,
    tx_accumulator: InMemoryAccumulator<ChannelTransactionAccumulatorHasher>,
}

impl AppliedTrees {
    pub fn version_and_state_root(&self) -> (Option<Version>, HashValue) {
        let num_leaves = self.tx_accumulator.num_leaves() as u64;
        let version = if num_leaves > 0 {
            Some(num_leaves - 1)
        } else {
            None
        };
        (version, self.state_tree.root_hash())
    }
}

impl Drop for AppliedTrees {
    fn drop(&mut self) {
        self.state_tree.prune();
    }
}

#[derive(Debug)]
pub struct TxApplier {
    applied_trees: AppliedTrees,
    applied_state_cache: AppliedStateCache,
    store: ChannelStore<ChannelDB>,
}

impl TxApplier {
    #[inline]
    pub fn participant_address(&self) -> AccountAddress {
        self.store.db().participant_address()
    }

    #[inline]
    pub fn owner_address(&self) -> AccountAddress {
        self.store.db().owner_address()
    }
}

impl TxApplier {
    pub fn new(store: ChannelStore<ChannelDB>) -> Self {
        let startup_info = store
            .get_startup_info()
            .expect("Fail to read startup info from storage");

        let (state_root_hash, frozen_subtrees_in_accumulator, num_leaves_in_accumulator, epoch) =
            match startup_info {
                Some(info) => {
                    info!("Startup info read from DB: {:?}.", info);
                    let ledger_info = info.ledger_info;

                    (
                        info.account_state_root_hash,
                        info.ledger_frozen_subtree_hashes,
                        info.latest_version + 1,
                        ledger_info.epoch(),
                    )
                }
                None => {
                    info!("Startup info is empty. Will start from GENESIS.");
                    (*SPARSE_MERKLE_PLACEHOLDER_HASH, vec![], 0, 0)
                }
            };
        let applied_trees = AppliedTrees {
            epoch,
            state_tree: SparseMerkleTree::new(state_root_hash),
            tx_accumulator: InMemoryAccumulator::new(
                frozen_subtrees_in_accumulator,
                num_leaves_in_accumulator,
            )
            .expect("the startup info read from storage should be valid"),
        };
        let applied_states =
            Self::get_applied_state_and_proof(&store, applied_trees.version_and_state_root())
                .expect("fail to load applied state_and_proof from storage");

        Self {
            applied_trees,
            applied_state_cache: applied_states,
            store,
        }
    }

    pub fn apply(&mut self, tx_to_apply: ChannelTransactionToApply) -> Result<()> {
        let ChannelTransactionToApply {
            signed_channel_txn,
            write_set,
            travel: _,
            events,
            major_status,
            gas_used,
            ..
        } = tx_to_apply;
        let channel_seq_number = signed_channel_txn.raw_tx.channel_sequence_number();
        ensure!(
            channel_seq_number == self.applied_trees.tx_accumulator.num_leaves(),
            "tx channel seq number mismatched"
        );

        let witness_states = self.process_write_set(write_set.as_ref())?;

        let new_state_tree = Self::build_state_tree(
            &witness_states,
            &self.applied_trees.state_tree,
            &self.applied_state_cache.account_to_proof_cache,
        )?;
        let _event_tree = InMemoryAccumulator::<EventAccumulatorHasher>::default()
            .append(events.iter().map(CryptoHash::hash).collect_vec().as_slice());

        let (travel, write_set) = match write_set {
            None => (true, WriteSet::default()),
            Some(ws) => (false, ws),
        };

        let write_set_tree = InMemoryAccumulator::<WriteSetAccumulatorHasher>::default().append(
            write_set
                .iter()
                .map(|(ap, wp)| WriteSetItem(ap.clone(), wp.clone()).hash())
                .collect_vec()
                .as_slice(),
        );
        let txn_info = ChannelTransactionInfo::new(
            signed_channel_txn.hash(),
            write_set_tree.root_hash(),
            new_state_tree.root_hash(),
            HashValue::default(), // TODO: event_tree.root_hash(),
            major_status,
            travel,
            gas_used,
        );

        let new_txn_accumulator = self
            .applied_trees
            .tx_accumulator
            .append(vec![txn_info.hash()].as_slice());

        debug_assert!(new_txn_accumulator.num_leaves() == channel_seq_number + 1);
        let new_epoch = if travel {
            self.applied_trees.epoch + 1
        } else {
            self.applied_trees.epoch
        };

        let ledger_info = LedgerInfo::new(
            channel_seq_number,
            new_txn_accumulator.root_hash(),
            new_epoch,
            get_current_timestamp().as_micros() as u64,
        );

        let txn_to_commit = ChannelTransactionToCommit::new(
            signed_channel_txn,
            write_set,
            travel,
            witness_states,
            events,
            major_status,
            gas_used,
        );

        self.store
            .save_tx(txn_to_commit, channel_seq_number, &Some(ledger_info), true)?;

        self.applied_trees = AppliedTrees {
            epoch: new_epoch,
            tx_accumulator: new_txn_accumulator,
            state_tree: new_state_tree,
        };

        let applied_state = Self::get_applied_state_and_proof(
            &self.store,
            self.applied_trees.version_and_state_root(),
        )?;

        // TODO: verify state
        self.applied_state_cache = applied_state;

        Ok(())
    }

    fn get_applied_state_and_proof(
        store: &ChannelStore<ChannelDB>,
        latest_version_and_state_root: (Option<Version>, HashValue),
    ) -> Result<AppliedStateCache> {
        let participant = store.db().participant_address();
        let owner = store.db().owner_address();

        let mut witness_states = HashMap::new();
        let mut states_proof = HashMap::new();

        for addr in vec![owner, participant].into_iter() {
            let (state_blob_option, state_proof) = match latest_version_and_state_root.0 {
                Some(version) => store.get_account_state_with_proof_by_version(addr, version)?,
                None => (None, SparseMerkleProof::new(None, vec![])),
            };
            state_proof
                .verify(
                    latest_version_and_state_root.1,
                    addr.hash(),
                    state_blob_option.as_ref(),
                )
                .map_err(|err| {
                    format_err!(
                        "Proof is invalid for address {:?} with state root hash {:?}: {}",
                        addr,
                        latest_version_and_state_root.1,
                        err
                    )
                })?;

            states_proof.insert(addr.hash(), state_proof);
            witness_states.insert(
                addr,
                state_blob_option
                    .as_ref()
                    .map(TryInto::try_into)
                    .transpose()?
                    .unwrap_or_default(),
            );
        }

        Ok(AppliedStateCache {
            account_to_btree_cache: witness_states,
            account_to_proof_cache: states_proof,
        })
    }

    /// based on `previous_state_tree` and account's `proof_reader`,
    /// calculate the `updated_blobs` state tree.
    fn build_state_tree(
        witness_states: &BTreeMap<AccountAddress, AccountStateBlob>,
        parent_state_tree: &SparseMerkleTree,
        state_proof: &HashMap<HashValue, SparseMerkleProof>,
    ) -> Result<SparseMerkleTree> {
        let current_state_tree = parent_state_tree;
        let proof_reader = AccountStateProofReader(state_proof);

        let new_state_tree = current_state_tree
            .update(
                witness_states
                    .iter()
                    .map(|(addr, value)| (addr.hash(), value.clone()))
                    .collect(),
                &proof_reader,
            )
            .expect("Fail to update state tree");
        Ok(new_state_tree)
    }

    fn process_write_set(
        &self,
        write_set: Option<&WriteSet>,
    ) -> Result<BTreeMap<AccountAddress, AccountStateBlob>> {
        // if write_set is none, it means the upper channel tx is travel
        match write_set {
            None => {
                let mut state = BTreeMap::new();
                let empty_state_blob = AccountStateBlob::try_from(&BTreeMap::new())?;
                state.insert(self.owner_address(), empty_state_blob.clone());
                state.insert(self.participant_address(), empty_state_blob);
                Ok(state)
            }
            Some(write_set) => {
                ensure!(
                    !write_set.is_empty(),
                    "write set should not be empty if channel tx is offchain"
                );
                let state: BTreeMap<AccountAddress, BTreeMap<Vec<u8>, Vec<u8>>> =
                    write_set.try_into()?;
                let mut blob_state = BTreeMap::new();
                for (addr, state_btree) in state.into_iter() {
                    blob_state.insert(addr, AccountStateBlob::try_from(&state_btree)?);
                }
                check_witness_state(
                    self.owner_address(),
                    self.participant_address(),
                    &blob_state,
                )?;
                Ok(blob_state)
            }
        }
    }
}

/// check witness_state should only contains channel participants' state
fn check_witness_state(
    sender: AccountAddress,
    receiver: AccountAddress,
    witness_states: &BTreeMap<AccountAddress, AccountStateBlob>,
) -> Result<()> {
    let valid = witness_states
        .keys()
        .all(|addr| *addr == sender || *addr == receiver);
    ensure!(
        valid,
        "witness_states should only contain sender or receiver data"
    );
    Ok(())
}

struct AccountStateProofReader<'a>(&'a HashMap<HashValue, SparseMerkleProof>);

impl<'a> ProofRead for AccountStateProofReader<'a> {
    fn get_proof(&self, key: HashValue) -> Option<&SparseMerkleProof> {
        self.0.get(&key)
    }
}

// Using current_timestamp
// because it's a bit hard to generate incremental timestamps
fn get_current_timestamp() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Timestamp generated is before the UNIX_EPOCH!")
}
