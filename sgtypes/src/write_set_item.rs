// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::hash::WriteSetItemHasher;
use super::impl_hash;
use canonical_serialization::{
    CanonicalDeserialize, CanonicalDeserializer, CanonicalSerialize, CanonicalSerializer,
};
use failure::prelude::*;
use libra_types::access_path::AccessPath;
use libra_types::write_set::WriteOp;

#[derive(Debug, Clone, PartialEq)]
pub struct WriteSetItem(pub AccessPath, pub WriteOp);

impl CanonicalSerialize for WriteSetItem {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        serializer.encode_struct(&self.0)?.encode_struct(&self.1)?;
        Ok(())
    }
}

impl CanonicalDeserialize for WriteSetItem {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(WriteSetItem(
            deserializer.decode_struct()?,
            deserializer.decode_struct()?,
        ))
    }
}

impl_hash!(WriteSetItem, WriteSetItemHasher);
