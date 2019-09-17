use failure::prelude::*;
use types::access_path::DataPath;
use std::collections::BTreeMap;
use atomic_refcell::AtomicRefCell;
use std::sync::Arc;
use std::convert::TryFrom;
use types::account_config::{AccountResource, account_resource_path};
use star_types::account_resource_ext;
use types::account_state_blob::AccountStateBlob;
use types::transaction::Version;
use types::proof::SparseMerkleProof;

#[derive(Clone,Debug)]
pub struct AccountState {
    version: Version,
    state: BTreeMap<Vec<u8>, Vec<u8>>,
    proof: SparseMerkleProof,
}

impl AccountState {

    pub fn from_account_state_blob(version: Version, account_state_blob: Vec<u8>, proof: SparseMerkleProof) -> Result<Self> {
        let state = BTreeMap::try_from(&AccountStateBlob::from(account_state_blob))?;
        Ok(Self{
            version,
            state,
            proof,
        })
    }

    pub fn get(&self, path: &Vec<u8>) -> Option<Vec<u8>> {
        self.state.get(path).cloned()
    }

    pub fn get_state(&self, data_path: &DataPath) -> Option<Vec<u8>> {
        self.get(&data_path.to_vec())
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

    pub fn into_map(self) -> BTreeMap<Vec<u8>, Vec<u8>>{
        self.state
    }

}

impl Into<Vec<u8>> for &AccountState {
    fn into(self) -> Vec<u8> {
        let blob: AccountStateBlob = self.into();
        blob.into()
    }
}

impl Into<BTreeMap<Vec<u8>, Vec<u8>>> for AccountState {
    fn into(self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        self.into_map()
    }
}

impl Into<BTreeMap<Vec<u8>, Vec<u8>>> for &AccountState {
    fn into(self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        self.clone().into()
    }
}

impl Into<AccountStateBlob> for AccountState {
    fn into(self) -> AccountStateBlob {
        AccountStateBlob::try_from(&Into::<BTreeMap<Vec<u8>, Vec<u8>>>::into(self)).expect("serialize account fail.")
    }
}

impl Into<AccountStateBlob> for &AccountState {
    fn into(self) -> AccountStateBlob {
       self.clone().into()
    }
}
