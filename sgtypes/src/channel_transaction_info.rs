// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0
use crate::{hash::ChannelTransactionInfoHasher, impl_hash};
use canonical_serialization::{
    CanonicalDeserialize, CanonicalDeserializer, CanonicalSerialize, CanonicalSerializer,
};
use crypto::HashValue;
use failure::prelude::*;
use libra_types::vm_error::StatusCode;
#[cfg(any(test, feature = "testing"))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

/// `ChannelTransactionInfo` is the object we store in the transaction accumulator.
/// It consists of the transaction as well as the execution result of this transaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
pub struct ChannelTransactionInfo {
    /// The hash of this transaction.
    signed_transaction_hash: HashValue,

    /// the root hash of Merkle Accumulator storing all write op emitted during this transaction.
    write_set_root_hash: HashValue,

    /// The root hash of Sparse Merkle Tree describing the world state at the end of this
    /// transaction.
    state_root_hash: HashValue,

    /// The root hash of Merkle Accumulator storing all events emitted during this transaction.
    event_root_hash: HashValue,

    /// The major status. This will provide the general error class. Note that this is not
    /// particularly high fidelity in the presence of sub statuses but, the major status does
    /// determine whether or not the transaction is applied to the global state or not.
    major_status: StatusCode,
}

impl ChannelTransactionInfo {
    /// Constructs a new `TransactionInfo` object using signed transaction hash, state root hash
    /// and event root hash.
    pub fn new(
        signed_transaction_hash: HashValue,
        write_set_root_hash: HashValue,
        state_root_hash: HashValue,
        event_root_hash: HashValue,

        major_status: StatusCode,
    ) -> ChannelTransactionInfo {
        ChannelTransactionInfo {
            signed_transaction_hash,
            write_set_root_hash,
            state_root_hash,
            event_root_hash,

            major_status,
        }
    }

    /// Returns the hash of this transaction.
    pub fn signed_transaction_hash(&self) -> HashValue {
        self.signed_transaction_hash
    }

    /// Returns root hash of Sparse Merkle Tree describing the world state at the end of this
    /// transaction.
    pub fn state_root_hash(&self) -> HashValue {
        self.state_root_hash
    }

    /// the root hash of Merkle Accumulator storing all write op emitted during this transaction.
    pub fn write_set_hash(&self) -> HashValue {
        self.write_set_root_hash
    }
    /// Returns the root hash of Merkle Accumulator storing all events emitted during this
    /// transaction.
    pub fn event_root_hash(&self) -> HashValue {
        self.event_root_hash
    }

    pub fn major_status(&self) -> StatusCode {
        self.major_status
    }
}

impl CanonicalSerialize for ChannelTransactionInfo {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        serializer
            .encode_bytes(self.signed_transaction_hash.as_ref())?
            .encode_bytes(self.write_set_root_hash.as_ref())?
            .encode_bytes(self.state_root_hash.as_ref())?
            .encode_bytes(self.event_root_hash.as_ref())?
            .encode_u64(self.major_status.into())?;
        Ok(())
    }
}

impl CanonicalDeserialize for ChannelTransactionInfo {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            signed_transaction_hash: HashValue::from_slice(
                deserializer.decode_bytes()?.as_slice(),
            )?,
            write_set_root_hash: HashValue::from_slice(deserializer.decode_bytes()?.as_slice())?,
            state_root_hash: HashValue::from_slice(deserializer.decode_bytes()?.as_slice())?,
            event_root_hash: HashValue::from_slice(deserializer.decode_bytes()?.as_slice())?,
            major_status: StatusCode::try_from(deserializer.decode_u64()?)?,
        })
    }
}

impl_hash!(ChannelTransactionInfo, ChannelTransactionInfoHasher);
