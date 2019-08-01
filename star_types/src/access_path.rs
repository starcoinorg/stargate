// This is caused by deriving Arbitrary for AccessPath.
#![allow(clippy::unit_arg)]

use std::{
    fmt::{self, Formatter},
    slice::Iter,
    str::{self, FromStr},
};

use hex;
#[cfg(any(test, feature = "testing"))]
use proptest_derive::Arbitrary;
use radix_trie::TrieKey;
use serde::{Deserialize, Serialize};

use canonical_serialization::{
    CanonicalDeserialize, CanonicalDeserializer, CanonicalSerialize, CanonicalSerializer,
};
use crypto::hash::{CryptoHash, HashValue};
use failure::prelude::*;
use proto_conv::{FromProto, IntoProto};
use types::{access_path::Access, access_path::Accesses, account_address::AccountAddress, language_storage::{ModuleId, ResourceKey, StructTag}};
use types::account_config::account_struct_tag;

/// SEPARATOR is used as a delimiter between fields. It should not be a legal part of any identifier
/// in the language
const SEPARATOR: char = '/';

#[derive(
Clone,
Eq,
PartialEq,
Hash,
Serialize,
Deserialize,
Ord,
PartialOrd,
)]
pub enum DataPath {
    Resource { tag: StructTag },
    Code { module_id: ModuleId },
}

impl DataPath {
    pub fn to_vec(&self) -> Vec<u8> {
        self.into()
    }

    pub fn account_resource_data_path() -> Self {
        DataPath::Resource {
            tag: account_struct_tag(),
        }
    }

    pub fn code_data_path(module_id: ModuleId) -> Self {
        DataPath::Code { module_id }
    }
}

impl From<&DataPath> for Vec<u8> {
    fn from(path: &DataPath) -> Self {
        match path {
            DataPath::Resource { tag } => {
                let mut key = vec![];
                key.push(AccessPath::RESOURCE_TAG);
                key.append(&mut tag.hash().to_vec());
                key
            }
            DataPath::Code { module_id } => {
                let mut key = vec![];
                key.push(AccessPath::CODE_TAG);
                key.append(&mut module_id.hash().to_vec());
                key
            }
        }
    }
}

#[derive(
Clone,
Eq,
PartialEq,
Hash,
Serialize,
Deserialize,
Ord,
PartialOrd,
)]
pub enum AccountPath {
    Onchain { data_path: DataPath },
    Offchain { participant: AccountAddress, data_path: DataPath },
}

impl AccountPath {
    pub fn to_vec(&self) -> Vec<u8> {
        self.into()
    }
}

impl From<&AccountPath> for Vec<u8> {
    fn from(path: &AccountPath) -> Self {
        let mut key = vec![];
        match path {
            AccountPath::Onchain { data_path } => {
                key.push(0u8);
                key.append(&mut data_path.to_vec());
            }
            AccountPath::Offchain { participant, data_path } => {
                key.push(1u8);
                key.append(&mut participant.to_vec());
                key.append(&mut data_path.to_vec());
            }
        };
        key
    }
}

#[derive(
Clone,
Eq,
PartialEq,
Default,
Hash,
Serialize,
Deserialize,
Ord,
PartialOrd,
)]
//#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
//#[ProtoType(crate::proto::access_path::AccessPath)]
pub struct AccessPath {
    pub address: AccountAddress,
    pub path: Vec<u8>,
}

impl AccessPath {
    pub const CODE_TAG: u8 = 0;
    pub const RESOURCE_TAG: u8 = 1;

    pub fn new_for_account_path(address: AccountAddress, path: AccountPath) -> Self {
        AccessPath { address, path: path.to_vec() }
    }

    pub fn new_for_account_resource(address: AccountAddress) -> Self {
        Self::new_for_account_path(address, AccountPath::Onchain { data_path: DataPath::account_resource_data_path() })
    }

    pub fn new_for_code(address: AccountAddress, module_id: ModuleId) -> Self {
        Self::new_for_account_path(address, AccountPath::Onchain { data_path: DataPath::code_data_path(module_id) })
    }

    pub fn new(address: AccountAddress, path: Vec<u8>) -> Self {
        AccessPath { address, path }
    }

    pub fn into_libra_access_path(self) -> types::access_path::AccessPath {
        self.into()
    }
}


impl Into<types::access_path::AccessPath> for AccessPath {
    fn into(self) -> types::access_path::AccessPath {
        types::access_path::AccessPath {
            address: self.address,
            path: self.path,
        }
    }
}


impl fmt::Debug for AccessPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AccessPath {{ address: {:x}, path: {} }}",
            self.address,
            hex::encode(&self.path)
        )
    }
}

impl fmt::Display for AccessPath {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        if self.path.len() < 1 + HashValue::LENGTH {
            write!(f, "{:?}", self)
        } else {
            write!(f, "AccessPath {{ address: {:x}, ", self.address)?;
            match self.path[0] {
                Self::RESOURCE_TAG => write!(f, "type: Resource, ")?,
                Self::CODE_TAG => write!(f, "type: Module, ")?,
                tag => write!(f, "type: {:?}, ", tag)?,
            };
            write!(
                f,
                "hash: {:?}, ",
                hex::encode(&self.path[1..=HashValue::LENGTH])
            )?;
            write!(
                f,
                "suffix: {:?} }} ",
                String::from_utf8_lossy(&self.path[1 + HashValue::LENGTH..])
            )
        }
    }
}

impl CanonicalSerialize for AccessPath {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        serializer
            .encode_struct(&self.address)?
            .encode_variable_length_bytes(&self.path)?;
        Ok(())
    }
}

impl CanonicalDeserialize for AccessPath {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self> {
        let address = deserializer.decode_struct::<AccountAddress>()?;
        let path = deserializer.decode_variable_length_bytes()?;

        Ok(Self { address, path })
    }
}
