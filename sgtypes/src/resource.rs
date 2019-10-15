use canonical_serialization::SimpleSerializer;
use failure::prelude::*;
use libra_types::{
    account_config::{
        account_struct_tag, AccountResource,
    },
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

pub fn get_event_handle_struct_def() -> StructDef {
    StructDef::new(vec![Type::U64, Type::ByteArray])
}

