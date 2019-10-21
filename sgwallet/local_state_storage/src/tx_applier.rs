// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crypto::hash::{CryptoHash, HashValue};
use failure::prelude::*;
use libra_types::account_address::AccountAddress;
use libra_types::account_state_blob::AccountStateBlob;
use libra_types::proof::accumulator::Accumulator;
use libra_types::proof::SparseMerkleProof;
use libra_types::transaction::TransactionOutput;
use libra_types::write_set::{WriteOp, WriteSet, WriteSetMut};
use scratchpad::{ProofRead, SparseMerkleTree};
use sgstorage::channel_db::ChannelDB;
use sgstorage::channel_store::ChannelStore;
use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::TryFrom;
use std::rc::Rc;

pub type AccountState = HashMap<AccountAddress, BTreeMap<Vec<u8>, Vec<u8>>>;

/// channel's account states and proof in offchain.
pub struct ApplyState {
    state_tree: Rc<SparseMerkleTree>,
    account_states: RefCell<AccountState>,
    account_proof: RefCell<HashMap<HashValue, SparseMerkleProof>>,
    //    transaction_accumulator: Rc<Accumulator<TransactionAccumulatorHasher>>
}

impl ApplyState {
    pub fn state_tree(&self) -> &Rc<SparseMerkleTree> {
        &self.state_tree
    }
}

pub struct TxData {
    account_blobs: HashMap<AccountAddress, AccountStateBlob>,
}

pub struct TxApplier {
    state: ApplyState,
    store: ChannelStore<ChannelDB>,
}

impl TxApplier {
    pub fn apply(&self, tx_output: TransactionOutput) -> Result<()> {
        let (tx_data, state_tree) = Self::process_vm_output(tx_output, &self.state)?;
        unimplemented!()
    }

    fn process_vm_output(
        vm_outout: TransactionOutput,
        parent_state: &ApplyState,
    ) -> Result<(TxData, Rc<SparseMerkleTree>)> {
        let mut current_state_tree = Rc::clone(parent_state.state_tree());
        let account_proof = parent_state.account_proof.borrow();
        let proof_reader = AccountStateProofReader(&account_proof);

        let (updated_blobs, state_tree) = Self::process_write_set(
            &mut parent_state.account_states.borrow_mut(),
            &proof_reader,
            vm_outout.write_set().clone(),
            current_state_tree.borrow(),
        )?;
        // TODO: check vm status ?
        let tx_data = TxData {
            account_blobs: updated_blobs,
        };
        Ok((tx_data, state_tree))
    }

    fn process_write_set(
        account_to_btree: &mut AccountState,
        proof_reader: &impl ProofRead,
        write_set: WriteSet,
        previous_state_tree: &SparseMerkleTree,
    ) -> Result<(
        HashMap<AccountAddress, AccountStateBlob>,
        Rc<SparseMerkleTree>,
    )> {
        let mut addrs = HashSet::new();
        for (ap, write_op) in write_set.into_iter() {
            let address: AccountAddress = ap.address;
            let path = ap.path;
            match account_to_btree.entry(address) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    let account_btree = entry.get_mut();
                    Self::update_account_btree(account_btree, path, write_op);
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    let mut account_btree = BTreeMap::new();
                    Self::update_account_btree(&mut account_btree, path, write_op);
                    entry.insert(account_btree);
                }
            }
            addrs.insert(address);
        }

        let mut updated_blobs = HashMap::new();

        for addr in addrs.iter() {
            let account_btree = account_to_btree.get(&addr).expect("Address should exist.");
            let account_blob = AccountStateBlob::try_from(account_btree)?;
            updated_blobs.insert(*addr, account_blob);
        }

        let state_tree = previous_state_tree
            .update(
                updated_blobs
                    .iter()
                    .map(|(addr, value)| (addr.hash(), value.clone()))
                    .collect(),
                proof_reader,
            )
            .expect("Failed to update state tree");

        Ok((updated_blobs, Rc::new(state_tree)))
    }

    fn update_account_btree(
        account_btree: &mut BTreeMap<Vec<u8>, Vec<u8>>,
        path: Vec<u8>,
        write_op: WriteOp,
    ) {
        match write_op {
            WriteOp::Value(new_value) => account_btree.insert(path, new_value),
            WriteOp::Deletion => account_btree.remove(&path),
        };
    }
}

struct AccountStateProofReader<'a>(&'a HashMap<HashValue, SparseMerkleProof>);

impl<'a> ProofRead for AccountStateProofReader<'a> {
    fn get_proof(&self, key: HashValue) -> Option<&SparseMerkleProof> {
        self.0.get(&key)
    }
}
