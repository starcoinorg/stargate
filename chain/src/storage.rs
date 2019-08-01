use crypto::HashValue;
use sparse_merkle::node_type::Node;
use types::transaction::SignedTransaction;

/// StateMerkleNodeSchema----node_hash：node
/// AccountStateSchema----blob_hash：blob
pub trait AccountStateStorage {
}

/// version：signed_transaction
pub trait TransactionStorage {
    fn insertTx(tx:SignedTransaction);
}