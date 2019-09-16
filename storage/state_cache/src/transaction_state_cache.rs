use std::collections::{HashMap, HashSet};

use crypto::{
    hash::CryptoHash,
    HashValue,
};
use failure::prelude::*;
use types::account_address::AccountAddress;
use types::account_state_blob::AccountStateBlob;
use types::access_path::AccessPath;
use atomic_refcell::AtomicRefCell;
use state_view::StateView;
use logger::prelude::*;
use types::language_storage::StructTag;
use state_store::{StateStore, StateViewPlus};
use star_types::resource_type::resource_def::{ResourceDef,StructDefResolve};
use jellyfish_merkle::{JellyfishMerkleTree, TreeReader, TreeUpdateBatch};
use crate::state_cache::AccountState;
use crate::data_view::AccountReader;
use types::{write_set::WriteSet, transaction::{TransactionOutput as LibraTransactionOutput, Version}};
use core::borrow::Borrow;

pub struct TransactionStateCache<'a, R: 'a + StructDefResolve + AccountReader> {
    account_states_cache: AtomicRefCell<HashMap<AccountAddress, AccountState>>,
    reader: &'a R,
}

impl<'a, R> TransactionStateCache<'a, R>
    where
        R: 'a + StructDefResolve + AccountReader + TreeReader
{
    pub fn apply_genesis_write_set_in_cache(ws: &WriteSet, reader: &'a R) -> Result<(HashValue, Vec<(AccountAddress, AccountStateBlob)>, TreeUpdateBatch)> {
        let mut account_set = HashSet::new();
        let mut account_vec = vec![];
        ws.iter().for_each(|(a, _op)| {
            if !account_set.contains(a.address.borrow()) {
                account_set.insert(a.address.borrow());
                account_vec.push(a.address.borrow())
            }
        });
        let genesis = true;
        let cache = Self::new_cache(genesis, None, account_vec, reader);
        cache.apply_write_set(ws, 0)?;

        let data = cache.get_blobs_with_address();

        let (hash, update_batch) = Self::apply_by_merkle_tree(genesis, None, cache.get_blobs(), reader)?;
        Ok((hash, data, update_batch))
    }

    pub fn apply_libra_output_in_cache(ver: Version, output: &LibraTransactionOutput, reader: &'a R) -> Result<(HashValue, Vec<(AccountAddress, AccountStateBlob)>, TreeUpdateBatch)> {
        let mut account_set = HashSet::new();
        let mut account_vec = vec![];
        output.write_set().iter().for_each(|(a, _op)| {
            if !account_set.contains(a.address.borrow()) {
                account_set.insert(a.address.borrow());
                account_vec.push(a.address.borrow())
            }
        });
        let genesis = false;
        let cache = Self::new_cache(genesis, Some(ver), account_vec, reader);

        cache.apply_libra_output(output)?;

        let data = cache.get_blobs_with_address();
        let (hash, update_batch) = Self::apply_by_merkle_tree(genesis, Some(ver), cache.get_blobs(), reader)?;
        Ok((hash, data, update_batch))
    }

    fn new_cache(genesis_flag: bool, ver: Option<Version>, account_vec: Vec<&AccountAddress>, reader: &'a R) -> Self {
        let accounts = match genesis_flag {
            true => vec![],
            false => {
                reader.get_accounts(ver.expect("ver s none.") + 1, account_vec).unwrap()
            }
        };
        let mut cache = HashMap::new();
        for (account, state) in accounts {
            cache.insert(account.clone(), state.clone());
        }
        TransactionStateCache { account_states_cache: AtomicRefCell::new(cache), reader }
    }

    fn get_blobs(&self) -> Vec<(HashValue, AccountStateBlob)> {
        let mut blob_vec = vec![];
        self.account_states_cache.borrow().iter().for_each(|(account_address, account_state)| {
            blob_vec.push((account_address.hash(), account_state.to_blob()))
        });
        blob_vec
    }

    fn get_blobs_with_address(&self) -> Vec<(AccountAddress, AccountStateBlob)> {
        let mut blob_vec = vec![];
        self.account_states_cache.borrow().iter().for_each(|(account_address, account_state)| {
            blob_vec.push((account_address.clone(), account_state.to_blob()))
        });
        blob_vec
    }

    fn apply_by_merkle_tree(genesis_flag: bool, ver: Option<Version>, blob_sets: Vec<(HashValue, AccountStateBlob)>, reader: &'a R) -> Result<(HashValue, TreeUpdateBatch)> {
        let (root_hashes, tree_update_batch) = JellyfishMerkleTree::new(reader).put_blob_sets(vec![blob_sets], match genesis_flag {
            true => 0,
            false => {
                ver.expect("ver is none.") + 1
            }
        })?;
        Ok((root_hashes[0], tree_update_batch))
    }

    fn get_by_access_path(&self, access_path: &AccessPath) -> Option<Vec<u8>> {
        self.account_states_cache.borrow().get(&access_path.address).and_then(|state| state.get(&access_path.path))
    }

    fn exist_account(&self, address: &AccountAddress) -> bool {
        self.account_states_cache.borrow().contains_key(address)
    }

    fn ensure_account_state(&self, address: &AccountAddress) {
        if !self.exist_account(address) {
            let account_state = AccountState::new();
            self.account_states_cache.borrow_mut().insert(*address, account_state);
        }
    }
}

impl<'a, R> StateView for TransactionStateCache<'a, R>
    where
        R: 'a + StructDefResolve + AccountReader + TreeReader {
    fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        Ok(self.get_by_access_path(access_path))
    }

    fn multi_get(&self, access_paths: &[AccessPath]) -> Result<Vec<Option<Vec<u8>>>> {
        Ok(access_paths.iter().map(|path| -> Option<Vec<u8>> {
            self.get_by_access_path(path)
        }).collect())
    }

    fn is_genesis(&self) -> bool {
        self.account_states_cache.borrow().is_empty()
    }
}

impl<'a, R> StateViewPlus for TransactionStateCache<'a, R>
    where
        R: 'a + StructDefResolve + AccountReader + TreeReader {}

impl<'a, R> StateStore for TransactionStateCache<'a, R>
    where
        R: 'a + StructDefResolve + AccountReader + TreeReader {
    fn update(&self, access_path: &AccessPath, value: Vec<u8>) -> Result<()> {
        self.ensure_account_state(&access_path.address);
        let mut states = self.account_states_cache.borrow_mut();
        let account_state = states.get_mut(&access_path.address).unwrap();
        account_state.update(access_path.path.clone(), value)?;
        Ok(())
    }

    fn delete(&self, access_path: &AccessPath) -> Result<()> {
        let mut states = self.account_states_cache.borrow_mut();
        let account_state = states.get_mut(&access_path.address);
        match account_state {
            Some(account_state) => {
                account_state.delete(&access_path.path)?;
            }
            None => { bail!("can not find account by address:{}", access_path.address); }
        };
        Ok(())
    }
}

impl<'a, R> StructDefResolve for TransactionStateCache<'a, R>
    where
        R: 'a + StructDefResolve + AccountReader + TreeReader {
    fn resolve(&self, tag: &StructTag) -> Result<ResourceDef> {
        self.reader.resolve(tag)
    }
}