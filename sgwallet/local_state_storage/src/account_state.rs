use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::sync::Arc;

use atomic_refcell::AtomicRefCell;
use itertools::Itertools;

use failure::prelude::*;
use star_types::account_resource_ext;
use types::access_path::DataPath;
use types::account_address::AccountAddress;
use types::account_config::{account_resource_path, AccountResource};
use types::account_state_blob::AccountStateBlob;
use types::proof::SparseMerkleProof;
use types::transaction::Version;

#[derive(Clone, Debug)]
pub struct AccountState {
    version: Version,
    state: BTreeMap<Vec<u8>, Vec<u8>>,
    proof: SparseMerkleProof,
}

impl AccountState {
    fn new() -> Self {
        Self {
            version: 0,
            state: BTreeMap::new(),
            proof: SparseMerkleProof::new(None, vec![]),
        }
    }

    fn insert(&mut self, path: DataPath, value: Vec<u8>) {
        self.state.insert(path.to_vec(), value);
    }

    pub fn from_account_state_blob(version: Version, account_state_blob: Vec<u8>, proof: SparseMerkleProof) -> Result<Self> {
        let state = BTreeMap::try_from(&AccountStateBlob::from(account_state_blob))?;
        Ok(Self {
            version,
            state,
            proof,
        })
    }

    pub fn version(&self) -> Version{
        self.version
    }

    pub fn proof(&self) -> &SparseMerkleProof{
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

    pub fn filter_channel_state(&self) -> BTreeMap<AccountAddress, BTreeMap<Vec<u8>, Vec<u8>>> {
        self.state.iter().map(|(k, v)| {
            (DataPath::from(k).expect("Parse DataPath should success"), v)
        }).filter(|(k, v)| k.is_channel_resource()).group_by(|(k, v)| -> AccountAddress{
            k.participant().expect("Channel Resource must contains participant.")
        }).into_iter().map(|(participant, group)| {
            println!("{}", participant);
            let mut state = BTreeMap::new();
            for (k, v) in group {
                state.insert(k.to_vec(), v.clone());
            }
            (participant, state)
        }).collect()
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
        AccountStateBlob::try_from(&Into::<BTreeMap<Vec<u8>, Vec<u8>>>::into(self)).expect("serialize account fail.")
    }
}

impl Into<AccountStateBlob> for &AccountState {
    fn into(self) -> AccountStateBlob {
        self.clone().into()
    }
}

#[cfg(test)]
mod tests {
    use types::account_config::AccountResource;

    use crate::AccountState;

    use super::*;
    use types::channel_account::ChannelAccountResource;

    #[test]
    fn test_from_account_state_blob() -> Result<()> {
        let account_resource = AccountResource::default();
        let mut account_state = AccountState::new();
        account_state.insert(DataPath::account_resource_data_path(), account_resource_ext::to_bytes(&account_resource)?);
        let account_state_blob = account_state.into();
        let proof = SparseMerkleProof::new(None, vec![]);
        let _account_state = AccountState::from_account_state_blob(0, account_state_blob, proof)?;
        Ok(())
    }

    #[test]
    fn test_filter_channel_state() -> Result<()> {
        let account_resource = AccountResource::default();
        let mut account_state = AccountState::new();
        account_state.insert(DataPath::account_resource_data_path(), account_resource_ext::to_bytes(&account_resource)?);
        let participant0 = AccountAddress::random();
        let participant1 = AccountAddress::random();
        account_state.insert(DataPath::channel_account_path(participant0), ChannelAccountResource::default().to_bytes());
        account_state.insert(DataPath::channel_account_path(participant1), ChannelAccountResource::default().to_bytes());
        let channel_states = account_state.filter_channel_state();
        assert_eq!(channel_states.len(), 2);
        assert_eq!(channel_states.get(&participant0).unwrap().len(),1);
        assert_eq!(channel_states.get(&participant1).unwrap().len(),1);
        Ok(())
    }
}