use std::ops::Deref;

use itertools::Itertools;

use canonical_serialization::{CanonicalDeserialize, CanonicalDeserializer, CanonicalSerialize, CanonicalSerializer};
use failure::prelude::*;
use types::language_storage::StructTag;
use vm_runtime_types::{loaded_data::struct_def::StructDef, value::MutVal};
use vm_runtime_types::loaded_data::types::Type;
use vm_runtime_types::value::Value;

pub struct Resource {
    tag: StructTag,
    def: StructDef,
    fields: Vec<Value>,
}

impl Resource {
    pub fn new(tag: StructTag, def: StructDef, fields: Vec<Value>) -> Self {
        //TODO check def and fields
        Self {
            tag,
            def,
            fields,
        }
    }

    pub fn decode(tag: StructTag, def: StructDef, deserializer: &mut impl CanonicalDeserializer) -> Result<Self> {
        let fields = Self::decode_fields(deserializer, &def)?;
        Ok(Self {
            tag,
            def,
            fields,
        })
    }

    pub fn encode_field(serializer: &mut impl CanonicalSerializer, field: &Value) -> Result<()> {
        match field {
            Value::Address(value) => { serializer.encode_struct(value)?; }
            Value::U64(value) => { serializer.encode_u64(*value)?; }
            Value::Bool(value) => { serializer.encode_bool(*value)?; }
            Value::ByteArray(value) => { serializer.encode_struct(value)?; }
            Value::String(value) => { serializer.encode_raw_bytes(value.as_ref())?; }
            Value::Struct(value) => {
                for sub_field in value {
                    Self::encode_field(serializer, sub_field.peek().deref())?;
                }
            }
        }
        Ok(())
    }

    pub fn decode_fields(deserializer: &mut impl CanonicalDeserializer, struct_def: &StructDef) -> Result<Vec<Value>> {
        struct_def.field_definitions().iter().map(|field_type| Self::decode_field(deserializer, field_type)).collect()
    }

    pub fn decode_field(deserializer: &mut impl CanonicalDeserializer, field_type: &Type) -> Result<Value> {
        let value = match field_type {
            Type::U64 => Value::U64(deserializer.decode_u64()?),
            Type::Bool => Value::Bool(deserializer.decode_bool()?),
            Type::ByteArray => Value::ByteArray(deserializer.decode_struct()?),
            Type::Address => Value::Address(deserializer.decode_struct()?),
            Type::Struct(def) => {
                let fields = Self::decode_fields(deserializer, def)?.iter().map(|value| MutVal::new(value.clone())).collect_vec();
                Value::Struct(fields)
            }
            _ => bail!("Unsupported type")
        };
        Ok(value)
    }
}


impl CanonicalSerialize for Resource {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        // TODO(drussi): the order in which these fields are serialized depends on some
        // implementation details in the VM.
        for field in &self.fields {
            Self::encode_field(serializer, field);
        }
        Ok(())
    }
}
