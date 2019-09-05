#[cfg(test)]
mod state_storage_test;
pub mod sparse_merkle;
mod transaction_state_cache;

use std::collections::{HashMap, BTreeMap};

use crypto::{
    hash::CryptoHash,
    HashValue,
};
use failure::prelude::*;
use types::account_address::AccountAddress;
use types::account_state_blob::AccountStateBlob;
use types::proof::SparseMerkleProof;
use types::access_path::{AccessPath, DataPath};
use std::convert::TryFrom;
use std::sync::Arc;
use crate::sparse_merkle::ProofRead;
use atomic_refcell::AtomicRefCell;
use star_types::channel_transaction::{ChannelTransaction};
use types::account_config::{AccountResource, account_resource_path};
use state_view::StateView;
use logger::prelude::*;
use star_types::change_set::StructDefResolve;
use types::language_storage::StructTag;
use types::{write_set::WriteSet, transaction::Version};
use struct_cache::StructCache;
use star_types::account_resource_ext;
use star_types::resource_type::resource_def::ResourceDef;
use jellyfish_merkle::{node_type::{NodeKey, Node}, JellyfishMerkleTree, TreeReader, TreeUpdateBatch};
use transaction_state_cache::TransactionStateCache;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone)]
pub struct AccountState {
    state: Arc<AtomicRefCell<BTreeMap<DataPath, Vec<u8>>>>
}

impl AccountState {
    pub fn new() -> Self {
        Self {
            state: Arc::new(AtomicRefCell::new(BTreeMap::new())),
        }
    }

    pub fn from_account_state_blob(account_state_blob: Vec<u8>) -> Result<Self> {
        let state = Self::new();
        let bmap = BTreeMap::try_from(&AccountStateBlob::from(account_state_blob))?;
        let updates = bmap.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        Self::update_state(&state, updates)?;
        Ok(state)
    }

    fn update_state(state: &AccountState, updates: Vec<(Vec<u8>, Vec<u8>)>) -> Result<()> {
        for (path, value) in updates {
            state.update(path, value)?;
        }
        Ok(())
    }

    /// update path resource and return new root.
    pub fn update(&self, path: Vec<u8>, value: Vec<u8>) -> Result<HashValue> {
        let data_path = DataPath::from(path.as_slice())?;
        self.do_update(data_path, value);
        Ok(self.root_hash())
    }

    fn do_update(&self, data_path: DataPath, value: Vec<u8>) {
        self.state.borrow_mut().insert(data_path, value);
    }

    pub fn get(&self, path: &Vec<u8>) -> Option<Vec<u8>> {
        self.get_state(&DataPath::from(path.as_slice()).unwrap())
    }

    pub fn get_state(&self, data_path: &DataPath) -> Option<Vec<u8>> {
        self.state.borrow().get(data_path).cloned()
    }

    pub fn delete(&self, path: &Vec<u8>) -> Result<HashValue> {
        self.delete_state(&DataPath::from(path.as_slice())?)
    }

    pub fn delete_state(&self, path: &DataPath) -> Result<HashValue> {
        self.state.borrow_mut().remove(path);
        Ok(self.root_hash())
    }

    pub fn get_account_resource(&self) -> Option<AccountResource> {
        self.get(&account_resource_path())
            .and_then(|value| account_resource_ext::from_bytes(&value).ok())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.into()
    }

    pub fn to_blob(&self) -> AccountStateBlob {
        self.into()
    }

    pub fn root_hash(&self) -> HashValue {
        //TODO use another hasher.
        let blob: AccountStateBlob = self.into();
        blob.hash()
    }
}

impl Into<Vec<u8>> for &AccountState {
    fn into(self) -> Vec<u8> {
        let blob: AccountStateBlob = self.into();
        blob.into()
    }
}

impl Into<BTreeMap<Vec<u8>, Vec<u8>>> for &AccountState {
    fn into(self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let map = &*self.state.borrow();
        map.iter().map(|(k, v)| (k.to_vec(), v.to_vec())).collect()
    }
}

impl Into<AccountStateBlob> for &AccountState {
    fn into(self) -> AccountStateBlob {
        AccountStateBlob::try_from(&Into::<BTreeMap<Vec<u8>, Vec<u8>>>::into(self)).expect("serialize account fail.")
    }
}


#[derive(Default)]
struct ProofReader(HashMap<HashValue, SparseMerkleProof>);

impl ProofReader {
    fn new(key_with_proof: Vec<(HashValue, SparseMerkleProof)>) -> Self {
        ProofReader(key_with_proof.into_iter().collect())
    }
}

impl ProofRead for ProofReader {
    fn get_proof(&self, key: HashValue) -> Option<&SparseMerkleProof> {
        self.0.get(&key)
    }
}

pub struct StateStorage {
    struct_cache: Arc<StructCache>,
    merkle_nodes: Arc<AtomicRefCell<HashMap<NodeKey, Node>>>,
    next_version: AtomicU64,
}

impl StateStorage {
    pub fn new() -> Self {
        Self {
            struct_cache: Arc::new(StructCache::new()),
            merkle_nodes: Arc::new(AtomicRefCell::new(HashMap::new())),
            next_version: AtomicU64::new(0),
        }
    }

    fn get_least_version(&self) -> Version {
        let tmp = self.next_version.load(Ordering::SeqCst);
        if tmp > 0 {
            tmp - 1
        } else {
            tmp
        }
    }

    pub fn exist_account_by_version(&self, ver: Version, address: &AccountAddress) -> bool {
        match self.account_state(ver, address) {
            Some(_state) => true,
            _ => false
        }
    }

    pub fn exist_account(&self, address: &AccountAddress) -> bool {
        match self.account_state(self.get_least_version(), address) {
            Some(_state) => true,
            _ => false
        }
    }

    pub fn sequence_number_by_version(&self, ver: Version, address: &AccountAddress) -> Option<u64> {
        self.account_state(ver, address).and_then(|a_s: AccountState| -> Option<u64> {
            a_s.get_account_resource().map(|a_r: AccountResource| -> u64 { a_r.sequence_number() })
        })
    }

    pub fn sequence_number(&self, address: &AccountAddress) -> Option<u64> {
        self.account_state(self.get_least_version(), address).and_then(|a_s: AccountState| -> Option<u64> {
            a_s.get_account_resource().map(|a_r: AccountResource| -> u64 { a_r.sequence_number() })
        })
    }

    //TODO get with proof
    pub fn get_account_state_by_version(&self, ver: Version, address: &AccountAddress) -> Option<Vec<u8>> {
        let account_state = self.account_state(ver, address);
        match account_state {
            Some(state) => {
                Some(state.to_bytes())
            }
            None => None
        }
    }

    pub fn get_account_state(&self, address: &AccountAddress) -> Option<Vec<u8>> {
        let account_state = self.account_state(self.get_least_version(), address);
        match account_state {
            Some(state) => {
                Some(state.to_bytes())
            }
            None => None
        }
    }

    fn get_by_access_path_by_version(&self, ver: Version, access_path: &AccessPath) -> Option<Vec<u8>> {
        self.account_state(ver, &access_path.address).and_then(|state| state.get(&access_path.path))
    }

    fn get_by_access_path(&self, access_path: &AccessPath) -> Option<Vec<u8>> {
        self.account_state(self.get_least_version(), &access_path.address).and_then(|state| state.get(&access_path.path))
    }

    pub fn apply_txn(&self, txn: &ChannelTransaction) -> Result<HashValue> {
        TransactionStateCache::apply_write_set_in_cache(self.is_genesis(), self.get_least_version(), txn.witness_payload_write_set(), self).and_then(|(root_hash, tree_update_batch)| -> Result<HashValue> {
            self.store_merkle_node(tree_update_batch);
            self.next_version.fetch_add(1, Ordering::SeqCst);
            Ok(root_hash)
        })
    }

    pub fn apply_write_set(&self, write_set: &WriteSet) -> Result<HashValue> {
        TransactionStateCache::apply_write_set_in_cache(self.is_genesis(), self.get_least_version(), write_set, self).and_then(|(root_hash, tree_update_batch)| -> Result<HashValue> {
            self.store_merkle_node(tree_update_batch);
            self.next_version.fetch_add(1, Ordering::SeqCst);
            Ok(root_hash)
        })
    }

    pub fn apply_libra_output(&self, txn_output: &types::transaction::TransactionOutput) -> Result<HashValue> {
        TransactionStateCache::apply_libra_output_in_cache(self.is_genesis(), self.get_least_version(), txn_output, self).and_then(|(root_hash, tree_update_batch)| -> Result<HashValue> {
            self.store_merkle_node(tree_update_batch);
            self.next_version.fetch_add(1, Ordering::SeqCst);
            Ok(root_hash)
        })
    }

    fn store_merkle_node(&self, merkle_nodes: TreeUpdateBatch) {
        let mut merkle_nodes_mut = self.merkle_nodes.borrow_mut();
        merkle_nodes
            .node_batch
            .iter()
            .for_each(|(node_key, node)| {
                merkle_nodes_mut.insert(node_key.clone(), node.clone());
            });
    }

    fn account_state(&self, ver: Version, address: &AccountAddress) -> Option<AccountState> {
        if !self.is_genesis() {
            let (account_blob, _) = JellyfishMerkleTree::new(self).get_with_proof(address.hash(), ver).unwrap();
            match account_blob {
                Some(blob) => {
                    let account = AccountState::from_account_state_blob(blob.into()).unwrap();
                    Some(account)
                }
                None => {
                    None
                }
            }
        } else {
            None
        }
    }

    pub fn account_state_with_proof(&self, ver: Option<Version>, address: &AccountAddress) -> Option<(Version, Option<AccountStateBlob>, SparseMerkleProof)> {
        if !self.is_genesis() {
            let version = match ver {
                Some(v) => { v }
                None => { self.get_least_version() }
            };
            let (account_blob, proof) = JellyfishMerkleTree::new(self).get_with_proof(address.hash(), version).unwrap();
            Some((version, account_blob, proof))
        } else {
            None
        }
    }

    pub fn root_hash(&self) -> HashValue {
        self.root_node(self.get_least_version(), &AccountAddress::default())
    }

    fn root_node(&self, ver: Version, address: &AccountAddress) -> HashValue {
        JellyfishMerkleTree::new(self).get_with_proof(address.hash(), ver).unwrap().1.siblings().get(0).unwrap().clone()
    }
}

pub trait AccountReader {
    fn get_accounts(&self, ver: Version, account_address_vec: Vec<&AccountAddress>) -> Result<Vec<(AccountAddress, AccountState)>>;
}

impl AccountReader for StateStorage {
    fn get_accounts(&self, ver: Version, account_address_vec: Vec<&AccountAddress>) -> Result<Vec<(AccountAddress, AccountState)>> {
        let tree = JellyfishMerkleTree::new(self);

        let mut accounts = vec![];
        if !self.is_genesis() {
            account_address_vec.iter().for_each(|address| {
                let addr = address.clone().clone();
                let proof = tree.get_with_proof(addr.hash(), ver).unwrap().0;
                match proof {
                    Some(blob) => {
                        let account = AccountState::from_account_state_blob(blob.into()).unwrap();
                        accounts.push((addr, account))
                    }
                    None => {}
                };
            });
        }
        Ok(accounts)
    }
}

impl StateView for StateStorage {
    fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        Ok(self.get_by_access_path(access_path))
    }

    fn multi_get(&self, access_paths: &[AccessPath]) -> Result<Vec<Option<Vec<u8>>>> {
        Ok(access_paths.iter().map(|path| -> Option<Vec<u8>> {
            self.get_by_access_path(path)
        }).collect())
    }

    fn is_genesis(&self) -> bool {
        self.merkle_nodes.borrow().is_empty()
    }
}

impl StructDefResolve for StateStorage {
    fn resolve(&self, tag: &StructTag) -> Result<ResourceDef> {
        self.struct_cache.find_struct(tag, self)
    }
}

impl TreeReader for StateStorage {
    fn get_node(&self, node_key: &NodeKey) -> Result<Node> {
        if !self.is_genesis() {
            let node = match self.merkle_nodes.borrow().get(node_key) {
                Some(data) => { data.clone() }
                None => { Node::Null }
            };
            Ok(node)
        } else {
            Ok(Node::Null)
        }
    }
}

