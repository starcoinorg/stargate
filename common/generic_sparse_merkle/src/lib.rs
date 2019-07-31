pub mod blob;
#[cfg(test)]
mod sparse_merkle_test;
#[cfg(test)]
mod mock_tree_store;

use crypto::{
    hash::{CryptoHash, SPARSE_MERKLE_PLACEHOLDER_HASH},
    HashValue,
};
use failure::prelude::*;
use sparse_merkle::node_type::{BranchNode, ExtensionNode, LeafNode, Node};
use sparse_merkle::{SparseMerkleTree, TreeUpdateBatch, TreeReader};
use types::proof::SparseMerkleProof;
use types::{account_state_blob::AccountStateBlob, transaction::Version};

//TODO custom blob
pub type Blob = AccountStateBlob;

/// The hardcoded maximum height of a [`SparseMerkleTree`] in nibbles.
const ROOT_NIBBLE_HEIGHT: usize = HashValue::LENGTH * 2;

pub struct GenericSparseMerkleTree<'a, R: 'a + TreeReader> {
    tree: SparseMerkleTree<'a, R>,
}

impl<'a, R> GenericSparseMerkleTree<'a, R>
    where
        R: 'a + TreeReader,
{
    pub fn new(reader: &'a R) -> Self {
        let tree = SparseMerkleTree::new(reader);
        Self {
            tree,
        }
    }

    pub fn put_blob_set(
        &self,
        blob_set: Vec<(HashValue, Blob)>,
        root_hash: HashValue,
    ) -> Result<(HashValue, TreeUpdateBatch)> {
        self.tree.put_blob_set(
            blob_set
                .iter()
                .map(|(k, blob)| (k.clone(), Into::<AccountStateBlob>::into(blob.clone())))
                .collect(),
            0,
            root_hash,
        )
    }

    /// Returns the account state blob (if applicable) and the corresponding merkle proof.
    pub fn get_with_proof(
        &self,
        key: HashValue,
        root_hash: HashValue,
    ) -> Result<(Option<Blob>, SparseMerkleProof)> {
        self.tree.get_with_proof(key, root_hash).map(|(blob, proof)| (blob.map(|b| Blob::from(b)), proof))
    }

    #[cfg(test)]
    pub fn get(&self, key: HashValue, root_hash: HashValue) -> Result<Option<Blob>> {
        Ok(self.get_with_proof(key, root_hash)?.0)
    }
}
