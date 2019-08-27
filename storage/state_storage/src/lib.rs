//#[cfg(test)]
mod state_storage_test;
pub mod sparse_merkle;

use std::collections::{HashMap, BTreeMap};

use crypto::{
    hash::{CryptoHash, SPARSE_MERKLE_PLACEHOLDER_HASH},
    HashValue,
};
use failure::prelude::*;
use types::account_address::AccountAddress;
use types::account_state_blob::AccountStateBlob;
use types::proof::SparseMerkleProof;
use types::access_path::{AccessPath, DataPath};
use std::convert::TryFrom;
use itertools::Itertools;
use std::sync::Arc;
use crate::sparse_merkle::{SparseMerkleTree, ProofRead};
use atomic_refcell::AtomicRefCell;
use star_types::offchain_transaction::{OffChainTransaction, TransactionOutput};
use types::account_config::{AccountResource, account_resource_path};
use types::event::EventHandle;
use types::byte_array::ByteArray;
use canonical_serialization::{SimpleSerializer, CanonicalSerialize};
use state_view::StateView;
use logger::prelude::*;
use star_types::change_set::{ChangeSet, Changes, StructDefResolve};
use star_types::resource::Resource;
use types::language_storage::StructTag;
use lazy_static::lazy_static;
use vm_runtime_types::loaded_data::struct_def::StructDef;
use struct_cache::StructCache;
use state_store::{StateStore, StateViewPlus};
use star_types::account_resource_ext;
use star_types::resource_type::resource_def::ResourceDef;

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
        Self::update_state(&state, updates);
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
    global_state: Arc<AtomicRefCell<SparseMerkleTree>>,
    account_states: Arc<AtomicRefCell<HashMap<AccountAddress, AccountState>>>,
    struct_cache: Arc<StructCache>,
}

impl StateStorage {
    pub fn new() -> Self {
        Self {
            global_state: Arc::new(AtomicRefCell::new(SparseMerkleTree::new(*SPARSE_MERKLE_PLACEHOLDER_HASH))),
            account_states: Arc::new(AtomicRefCell::new(HashMap::new())),
            struct_cache: Arc::new(StructCache::new()),
        }
    }

    pub fn root_hash(&self) -> HashValue {
        self.global_state.borrow().root_hash()
    }

    pub fn exist_account(&self, address: &AccountAddress) -> bool {
        self.account_states.borrow().contains_key(address)
    }

    pub fn sequence_number(&self, address: &AccountAddress) -> Option<u64> {
        self.account_states.borrow().get(address).and_then(|a_s: &AccountState| -> Option<u64> {
            a_s.get_account_resource().map(|a_r: AccountResource| -> u64 { a_r.sequence_number() })
        })
    }

    #[deprecated]
    pub fn create_account(&self, address: AccountAddress, init_amount: u64) -> Result<HashValue> {
        if self.exist_account(&address) {
            bail!("account with address: {} already exist.", address);
        }
        info!("create account:{} init_amount:{}", address, init_amount);
        let mut state = AccountState::new();
        //TODO not directly create account
        let event_handle = EventHandle::new_from_address(&address, 0);
        let account_resource = AccountResource::new(init_amount, 0, ByteArray::new(address.to_vec()), false, event_handle.clone(), event_handle.clone());
        let mut serializer = SimpleSerializer::new();
        account_resource.serialize(&mut serializer);
        let value: Vec<u8> = serializer.get_output();
        state.update(account_resource_path(), value);
        self.update_account(address, state)
    }
    #[deprecated]
    fn update_account(&self, address: AccountAddress, account_state: AccountState) -> Result<HashValue> {
        {
            let account_root_hash = account_state.root_hash();
            self.account_states.borrow_mut().insert(address, account_state);
            let mut global_state = self.global_state.borrow_mut();
            *global_state = global_state.update(vec![(address.hash(), AccountStateBlob::from(account_root_hash.to_vec()))], &ProofReader::default()).unwrap();
        }
        return Ok(self.root_hash());
    }

    //TODO get with proof
    pub fn get_account_state(&self, address: &AccountAddress) -> Option<Vec<u8>> {
        self.account_states.borrow().get(address).map(|state| state.to_bytes())
    }

    fn ensure_account_state(&self, address: &AccountAddress) {
        if !self.exist_account(address) {
            let account_state = AccountState::new();
            self.account_states.borrow_mut().insert(*address, account_state);
        }
    }

    fn get_by_access_path(&self, access_path: &AccessPath) -> Option<Vec<u8>> {
        self.account_states.borrow().get(&access_path.address).and_then(|state| state.get(&access_path.path))
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
        debug!("is_genesis account_states {}", self.account_states.borrow().len());
        self.account_states.borrow().is_empty()
    }
}

impl StateViewPlus for StateStorage {}

impl StateStore for StateStorage {
    fn update(&self, access_path: &AccessPath, value: Vec<u8>) -> Result<()> {
        self.ensure_account_state(&access_path.address);
        let mut states = self.account_states.borrow_mut();
        //this account state must exist, so use unwrap.
        let mut account_state = states.get_mut(&access_path.address).unwrap();
        let account_root_hash = account_state.update(access_path.path.clone(), value)?;
        let mut global_state = self.global_state.borrow_mut();
        *global_state = global_state.update(vec![(access_path.address.hash(), AccountStateBlob::from(account_root_hash.to_vec()))], &ProofReader::default()).unwrap();
        Ok(())
    }

    fn delete(&self, access_path: &AccessPath) -> Result<()> {
        let mut states = self.account_states.borrow_mut();
        let account_state = states.get_mut(&access_path.address);
        match account_state {
            Some(account_state) => {
                let account_root_hash = account_state.delete(&access_path.path)?;
                let mut global_state = self.global_state.borrow_mut();
                *global_state = global_state.update(vec![(access_path.address.hash(), AccountStateBlob::from(account_root_hash.to_vec()))], &ProofReader::default()).unwrap();
            }
            None => { bail!("can not find account by address:{}", access_path.address); }
        };
        Ok(())
    }
}

impl StructDefResolve for StateStorage {
    fn resolve(&self, tag: &StructTag) -> Result<ResourceDef> {
        self.struct_cache.find_struct(tag, self)
    }
}


