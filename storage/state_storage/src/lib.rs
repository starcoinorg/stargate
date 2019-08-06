#[cfg(test)]
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
use star_types::access_path::AccessPath;
use types::access_path::Access;
use std::convert::TryFrom;
use std::cell::RefCell;
use itertools::Itertools;
use std::sync::Arc;
use crate::sparse_merkle::{SparseMerkleTree,ProofRead};
use atomic_refcell::AtomicRefCell;
use std::ops::Deref;

pub struct AccountState {
    state: Arc<AtomicRefCell<BTreeMap<Vec<u8>,Vec<u8>>>>
}

impl AccountState {
    pub fn new() -> Self {
        Self {
            state: Arc::new(AtomicRefCell::new(BTreeMap::new())),
        }
    }

    pub fn from_account_state_blob(account_state_blob: Vec<u8>) -> Result<Self>{
        let mut state = Self::new();
        let bmap = BTreeMap::try_from(&AccountStateBlob::from(account_state_blob))?;
        let updates = bmap.iter().map(|(k,v)|(k.clone(),v.clone())).collect();
        Self::update_state(&mut state, updates);
        Ok(state)
    }

    fn update_state(state: &mut AccountState, updates: Vec<(Vec<u8>, Vec<u8>)>) -> Result<()>{
        for (path, value) in updates {
            state.update(path , value)?;
        }
        Ok(())
    }

    /// update path resource and return new root.
    pub fn update(&mut self, path: Vec<u8>, value: Vec<u8>) -> Result<HashValue> {
        self.state.borrow_mut().insert(path, value);
        Ok(self.root_hash())
    }

    pub fn get(&self, path: &Vec<u8>) -> Option<Vec<u8>> {
        self.state.borrow().get(path).cloned()
    }

    pub fn delete(&mut self, path: &Vec<u8>) -> Result<HashValue> {
        self.state.borrow_mut().remove(path);
        Ok(self.root_hash())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
       self.into()
    }

    pub fn root_hash(&self) -> HashValue{
        //TODO use another hasher.
        let blob:AccountStateBlob = self.into();
        blob.hash()
    }
}

impl Into<Vec<u8>> for &AccountState {

    fn into(self) -> Vec<u8> {
        let blob:AccountStateBlob = self.into();
        blob.into()
    }

}

impl Into<AccountStateBlob> for &AccountState{

    fn into(self) -> AccountStateBlob {
        AccountStateBlob::try_from(&*self.state.borrow()).expect("serialize account fail.")
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
    account_states: HashMap<AccountAddress, AccountState>,
}

impl StateStorage {
    pub fn new() -> Self {
        let mut account_states = HashMap::new();
        account_states.insert(AccountAddress::default(), AccountState::new());
        Self {
            global_state: Arc::new(AtomicRefCell::new(SparseMerkleTree::new(*SPARSE_MERKLE_PLACEHOLDER_HASH))),
            account_states,
        }
    }

    pub fn root_hash(&self) -> HashValue {
        self.global_state.borrow().root_hash()
    }

    pub fn create_account(&mut self, address: AccountAddress) {
        self.account_states.insert(address, AccountState::new());
    }

    //TODO get with proof
    pub fn get_account_state(&self, address: &AccountAddress) -> Option<&AccountState> {
        self.account_states.get(address)
    }

    fn get_account_state_mut(&mut self, address: &AccountAddress) -> Option<&mut AccountState> {
        self.account_states.get_mut(address)
    }

    pub fn apply_write_set(&mut self, write_set: &WriteSet) -> Result<HashValue> {
        for (access_path, op) in write_set {
            match op {
                WriteOp::Value(value) => {
                    self.update(access_path.clone().into(), value.clone())?;
                },
                WriteOp::Deletion => {
                    self.delete(access_path.clone().into())?;
                }
            };
        }
        Ok(self.global_state.borrow().root_hash())
    }

    pub fn update(&mut self, access_path: AccessPath, value: Vec<u8>) -> Result<HashValue> {
        let account_state = self.get_account_state_mut(&access_path.address);
        match account_state {
            Some(account_state) => {
                let account_root_hash = account_state.update(access_path.path.clone(), value)?;
                let mut global_state = self.global_state.borrow_mut();
                *global_state = global_state.update(vec![(access_path.address.hash(), AccountStateBlob::from(account_root_hash.to_vec()))], &ProofReader::default()).unwrap();
            }
            None => { return bail!("can not find account by address:{}", access_path.address); }
        };
        Ok(self.global_state.borrow().root_hash())
    }

    pub fn delete(&mut self, path: AccessPath) -> Result<HashValue> {
        unimplemented!()
    }
}

