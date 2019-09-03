use failure::prelude::*;
use crate::write_set::WriteSet;
use crate::account_address::AccountAddress;
use crate::transaction::Script;
use crypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use canonical_serialization::{CanonicalSerialize, CanonicalSerializer, CanonicalDeserializer, CanonicalDeserialize};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChannelTransactionPayload{
    pub channel_sequence_number: u64,
    pub write_set: WriteSet,
    pub receiver: AccountAddress,
    pub script: Option<Script>,
    //TODO(jole) should include public key and signature at here?.
    pub receiver_public_key: Ed25519PublicKey,
    pub receiver_signature: Ed25519Signature
}

impl CanonicalSerialize for ChannelTransactionPayload{

    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        serializer.encode_u64(self.channel_sequence_number)?;
        serializer.encode_struct(&self.write_set)?;
        serializer.encode_struct(&self.receiver)?;
        serializer.encode_optional(&self.script)?;
        serializer.encode_bytes(&self.receiver_public_key.to_bytes())?;
        serializer.encode_bytes(&self.receiver_signature.to_bytes())?;
        Ok(())
    }
}

impl CanonicalDeserialize for ChannelTransactionPayload{

    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self> where
        Self: Sized {
        let channel_sequence_number = deserializer.decode_u64()?;
        let write_set = deserializer.decode_struct()?;
        let receiver = deserializer.decode_struct()?;
        let script = deserializer.decode_optional()?;
        let public_key_bytes = deserializer.decode_bytes()?;
        let signature_bytes = deserializer.decode_bytes()?;
        let receiver_public_key = Ed25519PublicKey::try_from(&public_key_bytes[..])?;
        let receiver_signature = Ed25519Signature::try_from(&signature_bytes[..])?;
        Ok(Self{
            channel_sequence_number,
            write_set,
            receiver,
            script,
            receiver_public_key,
            receiver_signature
        })
    }
}
