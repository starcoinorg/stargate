// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crypto::{hash::SPARSE_MERKLE_PLACEHOLDER_HASH, HashValue};
use mock_tree_store::MockTreeStore;
use types::proof::verify_sparse_merkle_element;

fn modify(original_key: &HashValue, n: usize, value: u8) -> HashValue {
    let mut key = original_key.to_vec();
    key[n] = value;
    HashValue::from_slice(&key).unwrap()
}

#[test]
fn test_insert_to_empty_tree() {
    let db = MockTreeStore::default();
    let tree = GenericSparseMerkleTree::new(&db);

    // Tree is initially empty. Root is a null node. We'll insert a key-value pair which creates a
    // leaf node.
    let key = HashValue::random();
    let value = Blob::from(vec![1u8, 2u8, 3u8, 4u8]);

    let (new_root, batch) = tree
        .put_blob_set(
            vec![(key, value.clone())],
            *SPARSE_MERKLE_PLACEHOLDER_HASH, /* root hash being based on */
        )
        .unwrap();
    //assert!(batch.retired_record_batch.is_empty());
    db.write_tree_update_batch(batch).unwrap();

    assert_eq!(tree.get(key, new_root).unwrap().unwrap(), value);
}

#[test]
fn test_insert_at_leaf_with_branch_created() {
    let db = MockTreeStore::default();
    let tree = GenericSparseMerkleTree::new(&db);

    let key1 = HashValue::new([0x00u8; HashValue::LENGTH]);
    let value1 = Blob::from(vec![1u8, 2u8]);

    let (root1, batch) = tree
        .put_blob_set(
            vec![(key1, value1.clone())],
            *SPARSE_MERKLE_PLACEHOLDER_HASH, /* root hash being based on */
        )
        .unwrap();
    //assert!(batch.retired_record_batch.is_empty());
    db.write_tree_update_batch(batch).unwrap();
    assert_eq!(tree.get(key1, root1).unwrap().unwrap(), value1);

    // Insert at the previous leaf node. Should generate a branch node at root.
    // Change the 1st nibble to 15.
    let key2 = modify(&key1, 0, 0xf0);
    let value2 = Blob::from(vec![3u8, 4u8]);

    let (root2, batch) = tree
        .put_blob_set(
            vec![(key2, value2.clone())],
            root1, /* root hash being based on */
        )
        .unwrap();
    //assert!(batch.retired_record_batch.is_empty());
    db.write_tree_update_batch(batch).unwrap();
    assert_eq!(tree.get(key1, root1).unwrap().unwrap(), value1);
    assert!(tree.get(key2, root1).unwrap().is_none());
    assert_eq!(tree.get(key2, root2).unwrap().unwrap(), value2);

    // get # of nodes
    assert_eq!(db.num_nodes(), 3);
    assert_eq!(db.num_blobs(), 2);

    let leaf1 = LeafNode::new(key1, value1.hash());
    let leaf2 = LeafNode::new(key2, value2.hash());
    let mut branch = BranchNode::default();
    branch.set_child(0, (leaf1.hash(), true /* is_leaf */));
    branch.set_child(15, (leaf2.hash(), true /* is_leaf */));
    assert_eq!(db.get_node(root1).unwrap(), leaf1.into());
    assert_eq!(db.get_node(leaf2.hash()).unwrap(), leaf2.into());
    assert_eq!(db.get_node(root2).unwrap(), branch.into());
}
