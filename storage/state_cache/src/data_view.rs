use crypto::{hash::CryptoHash, HashValue};
use std::{cell::RefCell, collections::{HashMap, BTreeMap}, sync::Arc, convert::TryInto};
use types::{transaction::Version, account_address::AccountAddress, proof::{verify_sparse_merkle_element, SparseMerkleProof}};
use types::access_path::AccessPath;
use std::collections::hash_map::Entry;
use failure::prelude::*;
use state_view::StateView;
use scratchpad::{AccountState};
use crate::state_cache::AccountState as StarAccountState;
use libradb::data_storage::ReadData;
use struct_cache::StructCache;
use types::language_storage::StructTag;
use star_types::resource_type::resource_def::{StructDefResolve,ResourceDef};
use jellyfish_merkle::{node_type::{NodeKey, Node}, JellyfishMerkleTree, TreeReader};
use core::borrow::Borrow;

pub struct StateDataView {
    reader: Arc<dyn ReadData>,
    struct_cache: StructCache,
}

impl StateDataView {
    pub fn new(
        reader: Arc<dyn ReadData>,
        struct_cache: StructCache,
    ) -> Self {
        Self {
            reader,
            struct_cache,
        }
    }

    pub fn latest_version(&self) -> Option<Version> {
        self.reader.latest_version()
    }

    pub fn latest_state_root(&self) -> Option<HashValue> {
        self.reader.latest_state_root()
    }
}

impl StateView for StateDataView {
    fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        let address = access_path.address;
        let path = &access_path.path;

        let address_hash = address.hash();
        let (blob, proof) = match self.latest_version() {
            Some(version) => self
                .reader
                .get_account_state_with_proof_by_version(address, version)?,
            None => (None, SparseMerkleProof::new(None, vec![])),
        };
        let latest_state_root = self.latest_state_root().expect("latest state root is none.");
        verify_sparse_merkle_element(
            latest_state_root,
            address.hash(),
            &blob,
            &proof,
        ).map_err(|err| {
            format_err!("Proof is invalid for address {:?} with state root hash {:?}: {}",
                address,
                latest_state_root,
                err
            )
        })?;

        match blob {
            Some(b) => {
                let data = b.into();
                let sas = StarAccountState::from_account_state_blob(data)?;
                Ok(sas.get(path))
            }
            None => { Ok(None) }
        }
    }

    fn multi_get(&self, _access_paths: &[AccessPath]) -> Result<Vec<Option<Vec<u8>>>> {
        unimplemented!();
    }

    fn is_genesis(&self) -> bool {
        match self.reader.genesis_state() {
            Ok(state) => {
                match state {
                    Some(is) => { is }
                    None => false
                }
            }
            Err(e) => false
        }
    }
}

impl StructDefResolve for StateDataView {
    fn resolve(&self, tag: &StructTag) -> Result<ResourceDef> {
        self.struct_cache.find_struct(tag, self)
    }
}

impl TreeReader for StateDataView {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        self.reader.get_state_node(node_key)
    }
}

pub trait AccountReader {
    fn get_accounts(&self, ver: Version, account_address_vec: Vec<&AccountAddress>) -> Result<Vec<(AccountAddress, StarAccountState)>>;
}

impl AccountReader for StateDataView {
    fn get_accounts(&self, ver: Version, account_address_vec: Vec<&AccountAddress>) -> Result<Vec<(AccountAddress, StarAccountState)>> {
        let tree = JellyfishMerkleTree::new(self);

        let mut accounts = vec![];
        if !self.is_genesis() {
            account_address_vec.iter().for_each(|address| {
                let addr = address.clone().clone();
                let proof = tree.get_with_proof(addr.hash(), ver).unwrap().0;
                match proof {
                    Some(blob) => {
                        let account = StarAccountState::from_account_state_blob(blob.into()).unwrap();
                        accounts.push((addr, account))
                    }
                    None => {}
                };
            });
        }
        Ok(accounts)
    }
}