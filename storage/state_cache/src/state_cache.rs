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
use scratchpad::ProofRead;
use atomic_refcell::AtomicRefCell;
use star_types::channel_transaction::ChannelTransaction;
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
use crate::transaction_state_cache::TransactionStateCache;
use std::sync::atomic::{AtomicU64, Ordering};
use std::rc::Rc;
use crate::data_view::StateDataView;

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

pub struct StateCache;

impl StateCache {

    pub fn exist_account(reader: &StateDataView, ver: Version, address: &AccountAddress) -> bool {
        match Self::account_state(reader, ver, address) {
            Some(_state) => true,
            _ => false
        }
    }

    pub fn sequence_number_by_version(reader: &StateDataView, ver: Version, address: &AccountAddress) -> Option<u64> {
        Self::account_state(reader,ver, address).and_then(|a_s: AccountState| -> Option<u64> {
            a_s.get_account_resource().map(|a_r: AccountResource| -> u64 { a_r.sequence_number() })
        })
    }

    pub fn get_account_state_by_version(reader: &StateDataView, ver: Version, address: &AccountAddress) -> Option<Vec<u8>> {
        let account_state = Self::account_state(reader, ver, address);
        match account_state {
            Some(state) => {
                Some(state.to_bytes())
            }
            None => None
        }
    }

    pub fn get_by_access_path_by_version(reader: &StateDataView, ver: Version, access_path: &AccessPath) -> Option<Vec<u8>> {
        Self::account_state(reader, ver, &access_path.address).and_then(|state| state.get(&access_path.path))
    }

    pub fn apply_genesis_write_set(reader: &StateDataView, write_set: &WriteSet) -> Result<(HashValue, Vec<(AccountAddress, AccountStateBlob)>)> {
        TransactionStateCache::apply_genesis_write_set_in_cache(write_set, reader)
            .and_then(|(root_hash, accounts, tree_update_batch)| {
                Ok((root_hash, accounts))
            })
    }

    pub fn apply_libra_output(reader: &StateDataView, txn_output: &types::transaction::TransactionOutput) -> Result<(HashValue, Vec<(AccountAddress, AccountStateBlob)>)> {
        TransactionStateCache::apply_libra_output_in_cache(reader.latest_version().expect("latest verion err."), txn_output, reader)
            .and_then(|(root_hash, accounts, tree_update_batch)| {
                Ok((root_hash, accounts))
            })
    }

    fn account_state(reader: &StateDataView, ver: Version, address: &AccountAddress) -> Option<AccountState> {
        let (account_blob, _) = JellyfishMerkleTree::new(reader).get_with_proof(address.hash(), ver).unwrap();
        match account_blob {
            Some(blob) => {
                let account = AccountState::from_account_state_blob(blob.into()).unwrap();
                Some(account)
            }
            None => {
                None
            }
        }
    }

    pub fn account_state_with_proof(reader: &StateDataView, ver: Version, address: &AccountAddress) -> Option<(Version, Option<AccountStateBlob>, SparseMerkleProof)> {
        let (account_blob, proof) = JellyfishMerkleTree::new(reader).get_with_proof(address.hash(), ver).unwrap();
        Some((ver, account_blob, proof))
    }
}