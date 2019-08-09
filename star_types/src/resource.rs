use std::ops::Deref;

use itertools::Itertools;

use canonical_serialization::{CanonicalDeserialize, CanonicalDeserializer, CanonicalSerialize, CanonicalSerializer, SimpleDeserializer};
use failure::prelude::*;
use types::language_storage::StructTag;
use vm_runtime_types::{loaded_data::struct_def::StructDef, value::MutVal};
use vm_runtime_types::loaded_data::types::Type;
use vm_runtime_types::value::Value;

#[derive(Clone, Debug)]
pub struct Resource {
    tag: StructTag,
    def: StructDef,
    fields: Vec<MutVal>,
}

impl Resource {
    pub fn new(tag: StructTag, def: StructDef, fields: Vec<MutVal>) -> Self {
        //TODO check def and fields
        Self {
            tag,
            def,
            fields,
        }
    }

    pub fn decode(tag: StructTag, def: StructDef, bytes: &Vec<u8>) -> Result<Self> {
        let value = Value::simple_deserialize(bytes, def.clone()).map_err(|vm_error|format_err!("decode resource fail:{:?}", vm_error))?;
        if let Value::Struct(fields) = value {
            Ok(Self {
                tag,
                def,
                fields,
            })
        } else {
            Err(format_err!("decode resource fail, expect struct but get:{:?}", value))
        }
    }

    pub fn encode(&self) -> Option<Vec<u8>> {
        Into::<Value>::into(self).simple_serialize()
    }
}

impl Into<Value> for Resource {
    fn into(self) -> Value {
        (&self).into()
    }
}

impl Into<Value> for &Resource {
    fn into(self) -> Value {
        Value::Struct(self.fields.clone())
    }
}