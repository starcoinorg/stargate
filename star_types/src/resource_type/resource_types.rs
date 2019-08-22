// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0
//! Loaded representation for runtime types.

use crate::resource_type::resource_def::ResourceDef;
use canonical_serialization::*;
use failure::prelude::*;
use types::language_storage::StructTag;


/// Resolved form of runtime types.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum ResourceType {
    Bool,
    U64,
    String,
    ByteArray,
    Address,
    Resource(StructTag,ResourceDef),
}

/// This isn't used by any normal code at the moment, but is used by the fuzzer to serialize types
/// alongside values.
impl CanonicalSerialize for ResourceType {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        use ResourceType::*;

        // Add a type for each tag.
        let _: &mut _ = match self {
            Bool => serializer.encode_u8(0x01)?,
            U64 => serializer.encode_u8(0x02)?,
            String => serializer.encode_u8(0x03)?,
            ByteArray => serializer.encode_u8(0x04)?,
            Address => serializer.encode_u8(0x05)?,
            Resource(struct_tag, struct_def) => {
                serializer.encode_u8(0x06)?;
                struct_tag.serialize(serializer)?;
                struct_def.serialize(serializer)?;
                serializer
            }
        };
        Ok(())
    }
}

impl CanonicalDeserialize for ResourceType {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self>
    where
        Self: Sized,
    {
        use ResourceType::*;

        let ty = match deserializer.decode_u8()? {
            0x01 => Bool,
            0x02 => U64,
            0x03 => String,
            0x04 => ByteArray,
            0x05 => Address,
            0x06 => Resource(StructTag::deserialize(deserializer)?,ResourceDef::deserialize(deserializer)?),
            other => bail!(
                "Error while deserializing type: found unexpected tag {:#x}",
                other
            ),
        };
        Ok(ty)
    }
}
