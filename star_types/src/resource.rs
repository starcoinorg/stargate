use std::ops::Deref;

use itertools::Itertools;

use canonical_serialization::{
    CanonicalDeserialize, CanonicalDeserializer, CanonicalSerialize, CanonicalSerializer,
    SimpleDeserializer, SimpleSerializer,
};
use failure::prelude::*;
use logger::prelude::*;
use types::{
    access_path::{Access, Accesses},
    account_address::AccountAddress,
    account_config::{
        account_struct_tag, coin_module_name, coin_struct_tag, core_code_address, AccountResource,
    },
    byte_array::ByteArray,
    identifier::Identifier,
    language_storage::StructTag,
};
use vm_runtime_types::{
    loaded_data::{struct_def::StructDef, types::Type},
    value::{Struct, Value},
};

/// resolve StructDef by StructTag.
pub trait StructDefResolve {
    fn resolve(&self, tag: &StructTag) -> Result<StructDef>;
}

#[derive(Clone, Debug)]
pub struct Resource(StructTag, Struct);

impl Resource {
    pub fn new(tag: StructTag, value: Struct) -> Self {
        Self(tag, value)
    }

    pub fn tag(&self) -> &StructTag {
        &self.0
    }

    pub fn new_from_account_resource(account_resource: AccountResource) -> Self {
        //this serialize and decode should never fail, so use unwrap.
        let out: Vec<u8> = SimpleSerializer::serialize(&account_resource).unwrap();
        Self::decode(account_struct_tag(), get_account_struct_def(), &out).expect("decode fail.")
    }

    pub fn decode(tag: StructTag, def: StructDef, bytes: &[u8]) -> Result<Self> {
        let struct_value = Value::simple_deserialize(bytes, def)
            .map_err(|vm_error| format_err!("decode resource fail:{:?}", vm_error))
            .and_then(|value| {
                value
                    .value_as()
                    .ok_or(format_err!("value is not struct type"))
            })?;
        Ok(Self::new(tag, struct_value))
    }

    pub fn encode(&self) -> Vec<u8> {
        Into::<Value>::into(self)
            .simple_serialize()
            .expect("serialize should not fail.")
    }
}

impl Into<Value> for Resource {
    fn into(self) -> Value {
        Value::struct_(self.1)
    }
}

impl Into<Value> for &Resource {
    fn into(self) -> Value {
        self.clone().into()
    }
}

impl std::cmp::PartialEq for Resource {
    fn eq(&self, other: &Self) -> bool {
        //TODO optimize
        self.encode() == other.encode()
    }
}

impl Into<(StructTag, Struct)> for Resource {
    fn into(self) -> (StructTag, Struct) {
        (self.0, self.1)
    }
}

pub fn get_account_struct_def() -> StructDef {
    let int_type = Type::U64;
    let byte_array_type = Type::ByteArray;
    let coin = Type::Struct(get_coin_struct_def());

    let event_handle = Type::Struct(get_event_handle_struct_def());

    StructDef::new(vec![
        byte_array_type,
        coin,
        Type::Bool,
        event_handle.clone(),
        event_handle.clone(),
        int_type.clone(),
    ])
}

pub fn get_coin_struct_def() -> StructDef {
    let int_type = Type::U64;
    StructDef::new(vec![int_type.clone()])
}

pub fn get_market_cap_struct_tag() -> StructTag {
    StructTag {
        module: coin_module_name().to_owned(),
        name: Identifier::new("MarketCap").unwrap(),
        address: core_code_address(),
        type_params: vec![],
    }
}

pub fn get_market_cap_struct_def() -> StructDef {
    let int_type = Type::U64;
    StructDef::new(vec![int_type.clone()])
}

pub fn get_mint_capability_struct_tag() -> StructTag {
    StructTag {
        module: coin_module_name().to_owned(),
        name: Identifier::new("MintCapability").unwrap(),
        address: core_code_address(),
        type_params: vec![],
    }
}

pub fn get_mint_capability_struct_def() -> StructDef {
    StructDef::new(vec![])
}

pub fn get_event_handle_struct_tag() -> StructTag {
    StructTag {
        module: Identifier::new("Event").unwrap(),
        name: Identifier::new("Handle").unwrap(),
        address: core_code_address(),
        type_params: vec![],
    }
}

pub fn get_event_handle_struct_def() -> StructDef {
    StructDef::new(vec![Type::U64, Type::ByteArray])
}

pub fn get_event_handle_id_generator_tag() -> StructTag {
    StructTag {
        module: Identifier::new("Event").unwrap(),
        name: Identifier::new("HandleIdGenerator").unwrap(),
        address: core_code_address(),
        type_params: vec![],
    }
}

pub fn get_event_handle_id_generator_def() -> StructDef {
    StructDef::new(vec![Type::U64])
}

pub fn get_block_module_tag() -> StructTag {
    StructTag {
        module: Identifier::new("Block").unwrap(),
        name: Identifier::new("T").unwrap(),
        address: core_code_address(),
        type_params: vec![],
    }
}

pub fn get_block_module_def() -> StructDef {
    StructDef::new(vec![Type::U64])
}
