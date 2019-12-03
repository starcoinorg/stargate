// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::account_resource_ext;
use failure::prelude::*;

use libra_types::{
    access_path::DataPath,
    account_config::{account_resource_path, AccountResource},
    account_state_blob::AccountStateBlob,
    proof::SparseMerkleProof,
    transaction::Version,
};
use std::{collections::BTreeMap, convert::TryFrom};

#[derive(Clone, Debug)]
pub struct AccountState {
    version: Version,
    state: BTreeMap<Vec<u8>, Vec<u8>>,
    proof: SparseMerkleProof,
}

impl AccountState {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            version: 0,
            state: BTreeMap::new(),
            proof: SparseMerkleProof::new(None, vec![]),
        }
    }

    #[cfg(test)]
    fn insert(&mut self, path: DataPath, value: Vec<u8>) {
        self.state.insert(path.to_vec(), value);
    }

    pub fn from_account_state_blob(
        version: Version,
        account_state_blob: Vec<u8>,
        proof: SparseMerkleProof,
    ) -> Result<Self> {
        let state = BTreeMap::try_from(&AccountStateBlob::from(account_state_blob))?;
        Ok(Self {
            version,
            state,
            proof,
        })
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn proof(&self) -> &SparseMerkleProof {
        &self.proof
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

    pub fn into_map(self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        self.state
    }
}

impl Into<Vec<u8>> for &AccountState {
    fn into(self) -> Vec<u8> {
        self.clone().into()
    }
}

impl Into<Vec<u8>> for AccountState {
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
        AccountStateBlob::try_from(&Into::<BTreeMap<Vec<u8>, Vec<u8>>>::into(self))
            .expect("serialize account fail.")
    }
}

impl Into<AccountStateBlob> for &AccountState {
    fn into(self) -> AccountStateBlob {
        self.clone().into()
    }
}

#[cfg(test)]
mod tests {
    use libra_types::account_config::AccountResource;

    use super::*;

    #[test]
    fn test_from_account_state_blob() -> Result<()> {
        let account_resource = AccountResource::default();
        let mut account_state = AccountState::new();
        account_state.insert(
            DataPath::account_resource_data_path(),
            account_resource_ext::to_bytes(&account_resource)?,
        );
        let account_state_blob = account_state.into();
        let proof = SparseMerkleProof::new(None, vec![]);
        let _account_state = AccountState::from_account_state_blob(0, account_state_blob, proof)?;
        Ok(())
    }
}
