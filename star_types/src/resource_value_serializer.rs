use crate::{
    resource_value::{MutResourceVal, ResourceValue},
    resource_type::{resource_def::ResourceDef, resource_types::ResourceType},
};
use canonical_serialization::*;
use failure::prelude::*;
use std::convert::TryFrom;
use types::{account_address::AccountAddress, byte_array::ByteArray};
use types::language_storage::StructTag;

impl ResourceValue {
    /// Serialize this value using `SimpleSerializer`.
    pub fn simple_serialize(&self) -> Option<Vec<u8>> {
        SimpleSerializer::<Vec<u8>>::serialize(self).ok()
    }

    /// Deserialize this value using `SimpleDeserializer` and a provided struct definition.
    pub fn simple_deserialize(blob: &[u8], struct_tag: StructTag, resource: ResourceDef) -> Result<ResourceValue> {
        let mut deserializer = SimpleDeserializer::new(blob);
        deserialize_struct(&mut deserializer, struct_tag,&resource)
    }
}

fn deserialize_struct(
    deserializer: &mut SimpleDeserializer,
    struct_tag: StructTag,
    struct_def: &ResourceDef,
) -> Result<ResourceValue> {
    let mut s_vals: Vec<MutResourceVal> = Vec::new();
    for field_type in struct_def.field_definitions() {
        match field_type {
            ResourceType::Bool => {
                if let Ok(b) = deserializer.decode_bool() {
                    s_vals.push(MutResourceVal::new(ResourceValue::Bool(b)));
                } else {
                    //TODO custom error.
                    bail!("DataFormatError");
                }
            }
            ResourceType::U64 => {
                if let Ok(val) = deserializer.decode_u64() {
                    s_vals.push(MutResourceVal::new(ResourceValue::U64(val)));
                } else {
                    bail!("DataFormatError");
                }
            }
            ResourceType::String => {
                if let Ok(bytes) = deserializer.decode_variable_length_bytes() {
                    if let Ok(s) = String::from_utf8(bytes) {
                        s_vals.push(MutResourceVal::new(ResourceValue::String(s)));
                        continue;
                    }
                }
                bail!("DataFormatError");
            }
            ResourceType::ByteArray => {
                if let Ok(bytes) = deserializer.decode_variable_length_bytes() {
                    s_vals.push(MutResourceVal::new(ResourceValue::ByteArray(ByteArray::new(bytes))));
                    continue;
                }
                bail!("DataFormatError");
            }
            ResourceType::Address => {
                if let Ok(bytes) = deserializer.decode_variable_length_bytes() {
                    if let Ok(addr) = AccountAddress::try_from(bytes) {
                        s_vals.push(MutResourceVal::new(ResourceValue::Address(addr)));
                        continue;
                    }
                }
                bail!("DataFormatError");
            }
            ResourceType::Resource(tag, s_fields) => {
                if let Ok(s) = deserialize_struct(deserializer, tag.clone(),s_fields) {
                    s_vals.push(MutResourceVal::new(s));
                } else {
                    bail!("DataFormatError");
                }
            }
        }
    }
    Ok(ResourceValue::Resource(struct_tag, s_vals))
}

impl CanonicalSerialize for ResourceValue {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        match self {
            ResourceValue::Address(addr) => {
                // TODO: this is serializing as a vector but we want just raw bytes
                // however the AccountAddress story is a bit difficult to work with right now
                serializer.encode_variable_length_bytes(addr.as_ref())?;
            }
            ResourceValue::Bool(b) => {
                serializer.encode_bool(*b)?;
            }
            ResourceValue::U64(val) => {
                serializer.encode_u64(*val)?;
            }
            ResourceValue::String(s) => {
                // TODO: must define an api for canonical serializations of string.
                // Right now we are just using Rust to serialize the string
                serializer.encode_variable_length_bytes(s.as_bytes())?;
            }
            ResourceValue::Resource(tag, vals) => {
                for mut_val in vals {
                    (*mut_val.peek()).serialize(serializer)?;
                }
            }
            ResourceValue::ByteArray(bytearray) => {
                serializer.encode_variable_length_bytes(bytearray.as_bytes())?;
            }
        }
        Ok(())
    }
}
