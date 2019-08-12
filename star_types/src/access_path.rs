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
use types::{account_address::AccountAddress, language_storage::{ModuleId, ResourceKey, StructTag}};
use types::account_config::account_struct_tag;
use lazy_static::lazy_static;

lazy_static!{
    pub static ref ACCOUNT_STRUCT_TAG:StructTag = account_struct_tag();
}

#[derive(Eq, Hash, Serialize, Deserialize, Debug, Clone, PartialEq, Ord, PartialOrd)]
pub enum Access {
    //TODO need support field name access?
    //Field(),
    Index(u64),
}

impl Access {
    pub fn new_with_index(idx: u64) -> Self {
        Access::Index(idx)
    }
}

impl FromStr for Access {
    type Err = ::std::num::ParseIntError;

    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
        Ok(Access::new_with_index(s.parse::<u64>()?))
    }
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Access::Index(i) => write!(f, "{}", i),
        }
    }
}

/// Non-empty sequence of field accesses
#[derive(Eq, Hash, Serialize, Deserialize, Debug, Clone, PartialEq, Ord, PartialOrd)]
pub struct Accesses(Vec<Access>);

/// SEPARATOR is used as a delimiter between fields. It should not be a legal part of any identifier
/// in the language
const SEPARATOR: char = '/';

impl Accesses {
    pub fn empty() -> Self {
        Accesses(vec![])
    }

    pub fn new(idx: u64) -> Self{
        Accesses(vec![Access::Index(idx)])
    }

    /// Add an index to the end of the sequence
    pub fn add_index_to_back(&mut self, idx: u64) {
        self.0.push(Access::Index(idx))
    }

    pub fn append(&mut self, accesses: &mut Accesses) {
        self.0.append(&mut accesses.0)
    }

    /// Returns the first field in the sequence and reference to the remaining fields
    pub fn split_first(&self) -> (&Access, &[Access]) {
        self.0.split_first().unwrap()
    }

    /// Return the last access in the sequence
    pub fn last(&self) -> &Access {
        self.0.last().unwrap() // guaranteed not to fail because sequence is non-empty
    }

    pub fn iter(&self) -> Iter<'_, Access> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_separated_string(&self) -> String {
        let mut path = String::new();
        for access in self.0.iter() {
            match access {
//                Access::Field(s) => {
//                    let access_str = s.name().as_ref();
//                    assert!(access_str != "");
//                    path.push_str(access_str)
//                }
                Access::Index(i) => path.push_str(i.to_string().as_ref()),
            };
            path.push(SEPARATOR);
        }
        path
    }

    pub fn take_nth(&self, new_len: usize) -> Accesses {
        assert!(self.0.len() >= new_len);
        Accesses(self.0.clone().into_iter().take(new_len).collect())
    }
}

impl<'a> IntoIterator for &'a Accesses {
    type Item = &'a Access;
    type IntoIter = Iter<'a, Access>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl From<Vec<Access>> for Accesses {
    fn from(accesses: Vec<Access>) -> Accesses {
        Accesses(accesses)
    }
}

impl From<Vec<u8>> for Accesses {
    fn from(mut raw_bytes: Vec<u8>) -> Accesses {
        let access_str = String::from_utf8(raw_bytes.split_off(HashValue::LENGTH + 1)).unwrap();
        let fields_str = access_str.split(SEPARATOR).collect::<Vec<&str>>();
        let mut accesses = vec![];
        for access_str in fields_str.into_iter() {
            if access_str != "" {
                accesses.push(Access::from_str(access_str).unwrap());
            }
        }
        Accesses::from(accesses)
    }
}

#[derive(
Clone,
Eq,
PartialEq,
Ord,
PartialOrd,
)]
pub enum DataPath<'a> {
    Code { module_id: &'a ModuleId },
    OnChainResource { tag: &'a StructTag },
    OffChainResource { participant: AccountAddress, tag: &'a StructTag },
}

impl <'a> DataPath<'a> {
    //TODO get index by enum
    pub const CODE_TAG: u8 = 0;
    pub const ON_CHAIN_RESOURCE_TAG: u8 = 1;
    pub const OFF_CHAIN_RESOURCE_TAG: u8 =2;

    pub fn to_vec(self) -> Vec<u8> {
        self.into()
    }

    pub fn account_resource_data_path() -> Self {
        Self::on_chain_resource_path(&ACCOUNT_STRUCT_TAG)
    }

    pub fn code_data_path(module_id: &'a ModuleId) -> Self {
        DataPath::Code { module_id }
    }

    pub fn on_chain_resource_path(tag: &'a StructTag) -> Self{
        DataPath::OnChainResource {
            tag,
        }
    }

    pub fn off_chain_resource_path(participant: AccountAddress, tag: &'a StructTag) -> Self{
        DataPath::OffChainResource {
            participant,
            tag,
        }
    }
}

impl <'a> From<DataPath<'a>> for Vec<u8> {
    fn from(path: DataPath<'a>) -> Self {
        match path {
            DataPath::Code { module_id } => {
                let mut key = vec![];
                key.push(DataPath::CODE_TAG);
                key.append(&mut module_id.hash().to_vec());
                key
            },
            DataPath::OnChainResource { tag } => {
                let mut key = vec![];
                key.push(DataPath::ON_CHAIN_RESOURCE_TAG);
                key.append(&mut tag.hash().to_vec());
                key
            },
            DataPath::OffChainResource {participant, tag} => {
                let mut key = vec![];
                key.push(DataPath::OFF_CHAIN_RESOURCE_TAG);
                key.append(&mut participant.hash().to_vec());
                key.push(b'/');
                key.append(&mut tag.hash().to_vec());
                key
            }
        }
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

    pub fn new_for_data_path(address: AccountAddress, path: DataPath) -> Self {
        AccessPath { address, path: path.to_vec() }
    }

    pub fn new_for_account_resource(address: AccountAddress) -> Self {
        Self::new_for_data_path(address, DataPath::account_resource_data_path() )
    }

    pub fn new_for_code(address: AccountAddress, module_id: &ModuleId) -> Self {
        Self::new_for_data_path(address, DataPath::code_data_path(module_id) )
    }

    pub fn new(address: AccountAddress, path: Vec<u8>) -> Self {
        AccessPath { address, path }
    }

    pub fn code_access_path(key: &ModuleId) -> AccessPath {
        Self::new_for_data_path(*key.address(), DataPath::code_data_path(key))
    }

    pub fn resource_access_path(key: &ResourceKey) -> AccessPath {
        Self::new_for_data_path(key.address(), DataPath::on_chain_resource_path(key.type_()))
    }

    pub fn off_chain_resource_access_path(account: AccountAddress, participant: AccountAddress, tag: &StructTag) -> AccessPath {
        Self::new_for_data_path(account, DataPath::off_chain_resource_path(participant, tag))
    }

    pub fn into_libra_access_path(self) -> types::access_path::AccessPath {
        self.into()
    }

    pub fn is_code(&self) -> bool {
        !self.path.is_empty() && self.path[0] == DataPath::CODE_TAG
    }

    pub fn is_on_chain_resource(&self) -> bool {
        !self.path.is_empty() && self.path[0] == DataPath::ON_CHAIN_RESOURCE_TAG
    }

    pub fn is_off_chain_resource(&self) -> bool {
        !self.path.is_empty() && self.path[0] == DataPath::OFF_CHAIN_RESOURCE_TAG
    }

    pub fn resource_tag_hash(&self) -> Option<HashValue>{
        if self.path.is_empty() {
            return None;
        }
        match self.path[0]{
            DataPath::CODE_TAG => None,
            DataPath::ON_CHAIN_RESOURCE_TAG => Some(HashValue::from_slice(&self.path.as_slice()[1..]).expect("invalid access path.")),
            DataPath::OFF_CHAIN_RESOURCE_TAG => {
                let parts = self.path.split(|byte|*byte == b'/').collect::<Vec<&[u8]>>();
                if parts.len() < 2 {
                    None
                }else {
                    HashValue::from_slice(parts[1]).ok()
                }
            }
            _ => None
        }
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

impl From<types::access_path::AccessPath> for AccessPath {
    fn from(access_path: types::access_path::AccessPath) -> Self {
        Self{
            address:access_path.address,
            path:access_path.path,
        }
    }
}

impl fmt::Debug for AccessPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AccessPath {{ address: {:x}, type:{}, path: {} }}",
            self.address,
            self.path[0],
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
                DataPath::ON_CHAIN_RESOURCE_TAG => write!(f, "type: OnChain Resource, ")?,
                DataPath::OFF_CHAIN_RESOURCE_TAG => write!(f, "type: OffChain Resource, ")?,
                DataPath::CODE_TAG => write!(f, "type: Module, ")?,
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
