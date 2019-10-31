// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    channel_transaction::ChannelTransaction, channel_transaction_sigs::ChannelTransactionSigs,
    hash::SignedChannelTransactionHasher, impl_hash,
};
use canonical_serialization::{
    CanonicalDeserialize, CanonicalDeserializer, CanonicalSerialize, CanonicalSerializer,
};
use failure::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedChannelTransaction {
    pub raw_tx: ChannelTransaction,
    pub sender_signature: ChannelTransactionSigs,
    pub receiver_signature: ChannelTransactionSigs,
}

impl CanonicalSerialize for SignedChannelTransaction {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        serializer
            .encode_struct(&self.raw_tx)?
            .encode_struct(&self.sender_signature)?
            .encode_struct(&self.receiver_signature)?;
        Ok(())
    }
}

impl CanonicalDeserialize for SignedChannelTransaction {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            raw_tx: deserializer.decode_struct()?,
            sender_signature: deserializer.decode_struct()?,
            receiver_signature: deserializer.decode_struct()?,
        })
    }
}

impl_hash!(SignedChannelTransaction, SignedChannelTransactionHasher);
