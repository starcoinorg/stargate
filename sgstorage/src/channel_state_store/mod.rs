use crate::schema::scoped_node_key::*;
use crate::schema::scoped_stale_node_index::*;
use crate::SgDB;
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
use schemadb::SchemaBatch;
use std::{collections::HashMap, sync::Arc};

pub struct ChannelStateStore {
    db: Arc<SgDB>,
    receiver_account_address: AccountAddress,
}

pub struct ChannelState {
    pub sender_state: Option<AccountStateBlob>,
    pub receiver_state: Option<AccountStateBlob>,
    pub sender_state_proof: SparseMerkleProof,
    pub receiver_state_proof: SparseMerkleProof,
}

impl ChannelStateStore {
    pub fn new(db: Arc<SgDB>, receiver_account_address: AccountAddress) -> Self {
        Self {
            db,
            receiver_account_address,
        }
    }

    pub fn get_state_with_proof_by_version(&self, version: Version) -> Result<ChannelState> {
        let (receiver_blob, receiver_proof) = JellyfishMerkleTree::new(self)
            .get_with_proof(self.receiver_account_address.hash(), version)?;
        let (sender_blob, sender_proof) = JellyfishMerkleTree::new(self)
            .get_with_proof(self.db.owner_account_address.hash(), version)?;
        Ok(ChannelState {
            sender_state: sender_blob,
            receiver_state: receiver_blob,
            sender_state_proof: sender_proof,
            receiver_state_proof: receiver_proof,
        })
    }

    pub fn put_channel_state_set(
        &self,
        channel_state_set: HashMap<AccountAddress, AccountStateBlob>,
        version: Version,
        schema_batch: &mut SchemaBatch,
    ) -> Result<HashValue> {
        let is_all_channel_related_data = channel_state_set.keys().into_iter().all(|addr| {
            self.receiver_account_address == *addr || self.db.owner_account_address == *addr
        });
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
            schema_batch.put::<ScopedJellyfishMerkleNodeSchema>(
                &ScopedNodeKey::new(self.receiver_account_address, node_key.clone()),
                node,
            )?;
        }
        // TODO(caojiafeng): handle stale node index
        for stale_node_index in tree_update_batch.stale_node_index_batch.iter() {
            schema_batch.put::<ScopedStaleNodeIndexSchema>(
                &ScopedStaleNodeIndex::new(self.receiver_account_address, stale_node_index.clone()),
                &(),
            )?;
        }
        Ok(new_root_hashes[0])
    }
}

impl TreeReader for ChannelStateStore {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let key = ScopedNodeKey::new(self.receiver_account_address, node_key.clone());
        self.db.get::<ScopedJellyfishMerkleNodeSchema>(&key)
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test;
