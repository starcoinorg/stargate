// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::channel_db::ChannelAddressProvider;
use crate::schema_db::SchemaDB;
use crypto::{hash::CryptoHash, HashValue};
use failure::prelude::*;
use jellyfish_merkle::{
    node_type::{LeafNode, Node, NodeKey},
    JellyfishMerkleTree, TreeReader,
};
use libra_types::proof::SparseMerkleProof;
use libra_types::{
    account_address::AccountAddress, account_state_blob::AccountStateBlob, transaction::Version,
};
use libradb::schema::{jellyfish_merkle_node::*, stale_node_index::*};
use schemadb::SchemaBatch;
use std::{collections::HashMap, sync::Arc};

#[derive(Clone)]
pub struct ChannelStateStore<S> {
    db: Arc<S>,
    owner: AccountAddress,
}

pub struct ChannelState {
    pub sender_state: Option<AccountStateBlob>,
    pub receiver_state: Option<AccountStateBlob>,
    pub sender_state_proof: SparseMerkleProof,
    pub receiver_state_proof: SparseMerkleProof,
}

impl<S> ChannelStateStore<S> {
    pub fn new(db: Arc<S>, owner: AccountAddress) -> Self {
        Self { db, owner }
    }
}

impl<S> ChannelStateStore<S>
where
    S: SchemaDB + ChannelAddressProvider,
{
    /// get this channel state of sender and receiver
    pub fn get_state_with_proof_by_version(&self, version: Version) -> Result<ChannelState> {
        let (receiver_blob, receiver_proof) =
            self.get_account_state_with_proof_by_version(self.db.participant_address(), version)?;
        let (sender_blob, sender_proof) =
            self.get_account_state_with_proof_by_version(self.owner, version)?;

        Ok(ChannelState {
            sender_state: sender_blob,
            receiver_state: receiver_blob,
            sender_state_proof: sender_proof,
            receiver_state_proof: receiver_proof,
        })
    }

    /// Get the account state blob given account address and root hash of state Merkle tree
    #[inline]
    pub fn get_account_state_with_proof_by_version(
        &self,
        address: AccountAddress,
        version: Version,
    ) -> Result<(Option<AccountStateBlob>, SparseMerkleProof)> {
        let (blob, proof) =
            JellyfishMerkleTree::new(self).get_with_proof(address.hash(), version)?;
        Ok((blob, proof))
    }

    pub fn put_channel_state_set(
        &self,
        channel_state_set: HashMap<AccountAddress, AccountStateBlob>,
        version: Version,
        schema_batch: &mut SchemaBatch,
    ) -> Result<HashValue> {
        let is_all_channel_related_data = channel_state_set
            .keys()
            .into_iter()
            .all(|addr| self.db.participant_address() == *addr || self.owner == *addr);
        ensure!(
            is_all_channel_related_data,
            "state_set contain invalid data"
        );

        let blob_set = channel_state_set
            .into_iter()
            .map(|(addr, blob)| (addr.hash(), blob))
            .collect::<Vec<_>>();

        let (new_root_hashes, tree_update_batch) =
            JellyfishMerkleTree::new(self).put_blob_sets(vec![blob_set], version)?;
        ensure!(
            new_root_hashes.len() == 1,
            "root_hashes must consist of a single value.",
        );
        for (node_key, node) in tree_update_batch.node_batch.iter() {
            schema_batch.put::<JellyfishMerkleNodeSchema>(node_key, node)?;
        }
        // TODO(caojiafeng): handle stale node index
        for stale_node_index in tree_update_batch.stale_node_index_batch.iter() {
            schema_batch.put::<StaleNodeIndexSchema>(stale_node_index, &())?;
        }
        Ok(new_root_hashes[0])
    }
}

impl<S> TreeReader for ChannelStateStore<S>
where
    S: SchemaDB,
{
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        self.db.get::<JellyfishMerkleNodeSchema>(node_key)
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test;
