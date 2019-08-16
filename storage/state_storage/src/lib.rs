//#[cfg(test)]
mod state_storage_test;
pub mod sparse_merkle;

use std::collections::{HashMap, BTreeMap};
use std::rc::Rc;

use crypto::{
    hash::{AccountStateBlobHasher, CryptoHash, CryptoHasher, SPARSE_MERKLE_PLACEHOLDER_HASH},
    HashValue,
};
use failure::prelude::*;
use types::account_address::AccountAddress;
use types::account_state_blob::AccountStateBlob;
use types::proof::SparseMerkleProof;
use types::write_set::{WriteOp, WriteSet};
use types::access_path::{AccessPath, DataPath, Accesses};
use types::access_path::Access;
use std::convert::TryFrom;
use std::cell::RefCell;
use itertools::Itertools;
use std::sync::Arc;
use crate::sparse_merkle::{SparseMerkleTree, ProofRead};
use atomic_refcell::AtomicRefCell;
use std::ops::Deref;
use star_types::offchain_transaction::OffChainTransaction;
use types::account_config::{AccountResource, account_resource_path, account_struct_tag, coin_struct_tag, COIN_MODULE_NAME, core_code_address, EventHandle};
use types::byte_array::ByteArray;
use canonical_serialization::{SimpleSerializer, CanonicalSerialize};
use state_view::StateView;
use logger::prelude::*;
use star_types::change_set::{ChangeSet, Changes, StructDefResolve, ChangeSetMut};
use star_types::resource::{Resource, get_account_struct_def, get_coin_struct_def, get_market_cap_struct_tag, get_market_cap_struct_def, get_mint_capability_struct_tag, get_mint_capability_struct_def, get_event_handle_struct_tag, get_event_handle_struct_def, get_event_handle_id_generator_tag, get_event_handle_id_generator_def};
use types::language_storage::StructTag;
use lazy_static::lazy_static;
use vm_runtime_types::loaded_data::struct_def::StructDef;
use struct_cache::StructCache;

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

    fn do_update(&self, data_path: DataPath, value: Vec<u8>){
        self.state.borrow_mut().insert(data_path, value);
    }

    pub fn apply_changes(&self, data_path: &DataPath, changes: &Changes, resolve: &dyn StructDefResolve) -> Result<HashValue> {
        match changes {
            Changes::Value(value) => {
                self.state.borrow_mut().insert(data_path.clone(), value.clone());
            },
            Changes::Deletion => {
                self.state.borrow_mut().remove(data_path);
            }
            Changes::Fields(fields) => {
                let old_resource = self.get_resource(data_path, resolve)?;
                match old_resource {
                    Some(mut old_resource) => {
                        debug!("apply changes: {:#?} to resource {:#?}", fields, old_resource);
                        old_resource.apply_changes(fields);
                        debug!("merged resource {:#?}", old_resource);
                        self.do_update(data_path.clone(), old_resource.encode());
                    },
                    None => {
                        let tag = data_path.resource_tag().ok_or(format_err!("get resource tag from path fail."))?;
                        let def = resolve.resolve(tag)?;
                        debug!("init new resource {:?} from change {:#?}", tag, fields);
                        let new_resource = Resource::from_changes(fields, &def);
                        debug!("result {:?}", new_resource);
                        self.do_update(data_path.clone(), new_resource.encode());
                    }
                }
            }
        };

        Ok(self.root_hash())
    }

    pub fn get(&self, path: &Vec<u8>) -> Option<Vec<u8>> {
        self.get_state(&DataPath::from(path.as_slice()).unwrap())
    }

    pub fn get_state(&self, data_path: &DataPath) -> Option<Vec<u8>>{
        self.state.borrow().get(data_path).cloned()
    }

    pub fn get_resource(&self, data_path: &DataPath, resolve: &dyn StructDefResolve) -> Result<Option<Resource>> {
        let tag = data_path.resource_tag().ok_or(format_err!("get resource tag from path fail."))?;
        let def = resolve.resolve(tag)?;

        Ok(self.get_state(data_path).and_then(|state|{
            Resource::decode(def, state.as_slice()).ok()
        }))
    }

    pub fn delete(&self, path: &Vec<u8>) -> Result<HashValue> {
        self.delete_state(&DataPath::from(path.as_slice())?)
    }

    pub fn delete_state(&self, path: &DataPath) -> Result<HashValue> {
        self.state.borrow_mut().remove(path);
        Ok(self.root_hash())
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

impl Into<BTreeMap<Vec<u8>,Vec<u8>>> for &AccountState {

    fn into(self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let map = &*self.state.borrow();
        map.iter().map(|(k,v)|(k.to_vec(), v.to_vec())).collect()
    }
}

impl Into<AccountStateBlob> for &AccountState {
    fn into(self) -> AccountStateBlob {
        AccountStateBlob::try_from(&Into::<BTreeMap<Vec<u8>,Vec<u8>>>::into(self)).expect("serialize account fail.")
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

    pub fn create_account(&self, address: AccountAddress, init_amount: u64) -> Result<HashValue> {
        if self.exist_account(&address) {
            bail!("account with address: {} already exist.", address);
        }
        info!("create account:{}", address);
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
        self.account_states.borrow().get(address).map(|state|state.to_bytes())
    }

    fn ensure_account_state(&self, address: &AccountAddress){
        if !self.exist_account(address){
            let account_state = AccountState::new();
            self.update_account(*address, account_state);
        }
    }

    fn get_by_access_path(&self, access_path: &AccessPath) -> Option<Vec<u8>> {
        self.account_states.borrow().get(&access_path.address).and_then(|state| state.get(&access_path.path))
    }

//    fn get_state(&self, access_path: &AccessPath) -> Option<&State>{
//        self.get_account_state(&access_path.address).and_then(|state| state.get_state(&access_path.data_path().unwrap()))
//    }

    pub fn get_resource(&self, access_path: &AccessPath) -> Result<Option<Resource>> {
        let states = self.account_states.borrow();
        let state = states.get(&access_path.address);
        match state {
            None => Ok(None),
            Some(state) => state.get_resource(&access_path.data_path().unwrap(),self)
        }
    }

    pub fn apply_txn(&self, txn: &OffChainTransaction) -> Result<HashValue> {
        self.apply_change_set(txn.output().change_set())
    }

    pub fn apply_write_set(&self, write_set: &WriteSet) -> Result<HashValue> {
        self.apply_change_set(&self.write_set_to_change_set(write_set)?)
    }

    pub fn write_set_to_change_set(&self, write_set: &WriteSet) -> Result<ChangeSet> {
        let change_set:Result<Vec<(AccessPath, Changes)>> = write_set.iter().map(|(ap,write_op)|{
            let changes = match write_op {
                WriteOp::Deletion => Changes::Deletion,
                WriteOp::Value(value) => if ap.is_code(){
                    Changes::Value(value.clone())
                }else{
                    let old_resource = self.get_resource(ap)?;
                    let new_resource = Resource::decode(self.resolve(&ap.resource_tag().ok_or(format_err!("get resource tag fail"))?)?, value.as_slice())?;

                    let field_changes = match old_resource {
                        Some(old_resource) => old_resource.diff(&new_resource)?,
                        None => new_resource.to_changes()
                    };
                    Changes::Fields(field_changes)
                }
            };
            Ok((ap.clone(), changes))
        }).collect();
        ChangeSetMut::new(change_set?).freeze()
    }

    pub fn apply_change_set(&self, change_set: &ChangeSet) -> Result<HashValue> {
        {
            for (access_path, changes) in change_set {
                self.apply_changes(access_path, changes);
            }
        }
        Ok(self.root_hash())
    }

    pub fn apply_changes(&self, access_path: &AccessPath, changes: &Changes) {
        self.ensure_account_state(&access_path.address);
        //this account state must exist, so use unwrap.
        let mut states = self.account_states.borrow_mut();
        let account_state = states.get_mut(&access_path.address).unwrap();
        //let resolve = &*self.struct_def_resolve;
        //TODO fix unwrap
        let data_path = &access_path.data_path().unwrap();
        account_state.apply_changes(data_path, changes, self);
    }


//    pub fn update(&mut self, access_path: &AccessPath, value: Vec<u8>) -> Result<HashValue> {
//        {
//            let account_state = self.get_account_state_or_create(&access_path.address);
//            let account_root_hash = account_state.update(access_path.path.clone(), value)?;
//            let mut global_state = self.global_state.borrow_mut();
//            *global_state = global_state.update(vec![(access_path.address.hash(), AccountStateBlob::from(account_root_hash.to_vec()))], &ProofReader::default()).unwrap();
//        }
//        Ok(self.global_state.borrow().root_hash())
//    }
//
    pub fn delete(&self, access_path: &AccessPath) -> Result<HashValue> {
        let mut states = self.account_states.borrow_mut();
        let account_state = states.get_mut(&access_path.address);
        match account_state {
            Some(account_state) => {
                let account_root_hash = account_state.delete(&access_path.path)?;
                let mut global_state = self.global_state.borrow_mut();
                *global_state = global_state.update(vec![(access_path.address.hash(), AccountStateBlob::from(account_root_hash.to_vec()))], &ProofReader::default()).unwrap();
            }
            None => { return bail!("can not find account by address:{}", access_path.address); }
        };
        Ok(self.global_state.borrow().root_hash())
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
        false
    }
}

impl  StructDefResolve for StateStorage
{

    fn resolve(&self, tag: &StructTag) -> Result<StructDef> {
        self.struct_cache.find_struct(tag, self)
    }
}


