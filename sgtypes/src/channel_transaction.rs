// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use std::{
    convert::TryFrom,
    fmt::{Display, Formatter},
};

use serde::{Deserialize, Serialize};

use canonical_serialization::{
    CanonicalDeserialize, CanonicalDeserializer, CanonicalSerialize, CanonicalSerializer,
    SimpleDeserializer, SimpleSerializer,
};
use crypto::{
    ed25519::{Ed25519PublicKey, Ed25519Signature},
    HashValue,
};
use failure::prelude::*;
use libra_types::transaction::TransactionArgument;
use libra_types::{
    account_address::AccountAddress,
    transaction::{ChannelWriteSetBody, RawTransaction, TransactionOutput, Version},
};
use std::time::Duration;

#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ChannelOp {
    Open,
    Execute {
        package_name: String,
        script_name: String,
    },
    Close,
}

impl ChannelOp {
    pub fn is_open(&self) -> bool {
        match self {
            ChannelOp::Open => true,
            _ => false,
        }
    }

    pub fn to_string(&self) -> String {
        format!("{}", self)
    }
}

impl CanonicalSerialize for ChannelOp {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        match self {
            ChannelOp::Open => {
                serializer.encode_u32(ChannelOpType::Open as u32)?;
            }
            ChannelOp::Execute {
                package_name,
                script_name,
            } => {
                serializer.encode_u32(ChannelOpType::Execute as u32)?;
                serializer.encode_string(package_name.as_str())?;
                serializer.encode_string(script_name.as_str())?;
            }
            ChannelOp::Close => {
                serializer.encode_u32(ChannelOpType::Close as u32)?;
            }
        }
        Ok(())
    }
}

impl CanonicalDeserialize for ChannelOp {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self>
    where
        Self: Sized,
    {
        let decoded_channel_op_type = deserializer.decode_u32()?;
        let channel_op_type = ChannelOpType::from_u32(decoded_channel_op_type);
        match channel_op_type {
            Some(ChannelOpType::Open) => Ok(ChannelOp::Open),
            Some(ChannelOpType::Execute) => {
                let package_name = deserializer.decode_string()?;
                let script_name = deserializer.decode_string()?;
                Ok(ChannelOp::Execute {
                    package_name,
                    script_name,
                })
            }
            Some(ChannelOpType::Close) => Ok(ChannelOp::Close),
            None => Err(format_err!(
                "ParseError: Unable to decode ChannelOpType, found {}",
                decoded_channel_op_type
            )),
        }
    }
}

impl Display for ChannelOp {
    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
        match self {
            ChannelOp::Open => write!(f, "open"),
            ChannelOp::Execute {
                package_name,
                script_name,
            } => write!(f, "{}.{}", package_name, script_name),
            ChannelOp::Close => write!(f, "close"),
        }
    }
}

enum ChannelOpType {
    Open = 0,
    Execute = 1,
    Close = 2,
}

impl ChannelOpType {
    fn from_u32(value: u32) -> Option<ChannelOpType> {
        match value {
            0 => Some(ChannelOpType::Open),
            1 => Some(ChannelOpType::Execute),
            2 => Some(ChannelOpType::Close),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct Witness {
    /// The witness_payload include txn output's write_set,
    /// Receiver can build a new txn with this payload, and submit to chain.
    pub witness_payload: ChannelWriteSetBody,
    pub witness_signature: Ed25519Signature,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChannelTransactionRequestPayload {
    Offchain {
        /// The witness_payload hash,
        witness_hash: HashValue,
        witness_signature: Ed25519Signature,
    },
    Travel {
        /// The txn output's write_set hash, for receiver to verify the output.
        /// TODO(jole) need hash the whole output?
        txn_write_set_hash: HashValue,
        /// The txn signature, for receiver can build a SignedTransaction with it and
        /// RawTransaction , then submit to chain.
        txn_signature: Ed25519Signature,
    },
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChannelTransactionRequest {
    /// The id of request
    request_id: HashValue,
    /// The global status version on this tx executed.
    version: Version,
    operator: ChannelOp,
    /// txn sender
    sender: AccountAddress,
    /// Sequence number of this transaction corresponding to sender's account.
    sequence_number: u64,
    /// txn receiver
    receiver: AccountAddress,
    /// Sequence number of this channel.
    channel_sequence_number: u64,
    /// The txn expiration time
    expiration_time: Duration,
    /// The request payload, depend on txn type.
    payload: ChannelTransactionRequestPayload,
    /// The sender's public key
    public_key: Ed25519PublicKey,

    args: Vec<TransactionArgument>,

    /// Maximal total gas specified by wallet to spend for this transaction.
    max_gas_amount: u64,
    /// Maximal price can be paid per gas.
    gas_unit_price: u64,
}

impl ChannelTransactionRequest {
    pub fn new(
        version: Version,
        operator: ChannelOp,
        sender: AccountAddress,
        sequence_number: u64,
        receiver: AccountAddress,
        channel_sequence_number: u64,
        expiration_time: Duration,
        payload: ChannelTransactionRequestPayload,
        public_key: Ed25519PublicKey,
        args: Vec<TransactionArgument>,
        max_gas_amount: u64,
        gas_unit_price: u64,
    ) -> Self {
        let request_id = Self::generate_request_id(sender, receiver, channel_sequence_number);
        Self {
            request_id,
            version,
            operator,
            sender,
            sequence_number,
            receiver,
            channel_sequence_number,
            expiration_time,
            payload,
            public_key,
            args,
            max_gas_amount,
            gas_unit_price,
        }
    }
    //TODO(jole) should use sequence_number?
    fn generate_request_id(
        sender: AccountAddress,
        receiver: AccountAddress,
        channel_sequence_number: u64,
    ) -> HashValue {
        let mut bytes = vec![];
        bytes.append(&mut sender.to_vec());
        bytes.append(&mut receiver.to_vec());
        bytes.append(&mut channel_sequence_number.to_be_bytes().to_vec());
        HashValue::from_sha3_256(bytes.as_slice())
    }

    pub fn request_id(&self) -> HashValue {
        self.request_id
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn operator(&self) -> &ChannelOp {
        &self.operator
    }

    pub fn payload(&self) -> &ChannelTransactionRequestPayload {
        &self.payload
    }

    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    pub fn is_travel_txn(&self) -> bool {
        match &self.payload {
            ChannelTransactionRequestPayload::Travel { .. } => true,
            _ => false,
        }
    }

    pub fn sender(&self) -> AccountAddress {
        self.sender
    }

    pub fn receiver(&self) -> AccountAddress {
        self.receiver
    }

    pub fn channel_sequence_number(&self) -> u64 {
        self.channel_sequence_number
    }

    pub fn sequence_number(&self) -> u64 {
        self.sequence_number
    }

    pub fn args(&self) -> &[TransactionArgument] {
        self.args.as_slice()
    }

    pub fn expiration_time(&self) -> Duration {
        self.expiration_time
    }

    pub fn max_gas_amount(&self) -> u64 {
        self.max_gas_amount
    }
    pub fn gas_unit_price(&self) -> u64 {
        self.gas_unit_price
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelTransactionRequestAndOutput {
    pub request: ChannelTransactionRequest,
    pub output: TransactionOutput,
    pub raw_txn: RawTransaction,
}

impl ChannelTransactionRequestAndOutput {
    pub fn new(
        request: ChannelTransactionRequest,
        output: TransactionOutput,
        raw_txn: RawTransaction,
    ) -> Self {
        Self {
            request,
            output,
            raw_txn,
        }
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChannelTransactionResponsePayload {
    //    Offchain(Witness),
    Offchain {
        /// receiver's signature on witness payload
        witness_payload_signature: Ed25519Signature,
    },
    Travel {
        /// For travel txn, receiver only need to signature txn payload.
        txn_payload_signature: Ed25519Signature,
    },
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChannelTransactionResponse {
    request_id: HashValue,
    channel_sequence_number: u64,
    payload: ChannelTransactionResponsePayload,
    /// The receiver's public key
    public_key: Ed25519PublicKey,
}

impl ChannelTransactionResponse {
    pub fn new(
        request_id: HashValue,
        channel_sequence_number: u64,
        payload: ChannelTransactionResponsePayload,
        public_key: Ed25519PublicKey,
    ) -> Self {
        Self {
            request_id,
            channel_sequence_number,
            payload,
            public_key,
        }
    }

    pub fn request_id(&self) -> HashValue {
        self.request_id
    }

    pub fn channel_sequence_number(&self) -> u64 {
        self.channel_sequence_number
    }

    pub fn payload(&self) -> &ChannelTransactionResponsePayload {
        &self.payload
    }

    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    pub fn is_travel_txn(&self) -> bool {
        match &self.payload {
            ChannelTransactionResponsePayload::Travel { .. } => true,
            _ => false,
        }
    }
}

impl CanonicalSerialize for Witness {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        serializer
            .encode_struct(&self.witness_payload)?
            .encode_bytes(&self.witness_signature.to_bytes())?;
        Ok(())
    }
}

impl CanonicalDeserialize for Witness {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self>
    where
        Self: Sized,
    {
        let witness_payload = deserializer.decode_struct()?;
        let witness_signature = deserializer.decode_struct()?;
        Ok(Self {
            witness_payload,
            witness_signature,
        })
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
enum ChannelTransactionType {
    Offchain = 0,
    Travel = 1,
}

impl ChannelTransactionType {
    fn from_u32(value: u32) -> Option<ChannelTransactionType> {
        match value {
            0 => Some(ChannelTransactionType::Offchain),
            1 => Some(ChannelTransactionType::Travel),
            _ => None,
        }
    }
}

impl CanonicalSerialize for ChannelTransactionRequestPayload {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        match self {
            ChannelTransactionRequestPayload::Offchain {
                witness_signature,
                witness_hash,
            } => {
                serializer
                    .encode_u32(ChannelTransactionType::Offchain as u32)?
                    .encode_bytes(witness_hash.as_ref())?
                    .encode_bytes(witness_signature.to_bytes().as_ref())?;
            }
            ChannelTransactionRequestPayload::Travel {
                txn_write_set_hash,
                txn_signature,
            } => {
                serializer
                    .encode_u32(ChannelTransactionType::Travel as u32)?
                    .encode_bytes(txn_write_set_hash.as_ref())?
                    .encode_bytes(&txn_signature.to_bytes())?;
            }
        }
        Ok(())
    }
}

impl CanonicalDeserialize for ChannelTransactionRequestPayload {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self>
    where
        Self: Sized,
    {
        let decoded_txn_type = deserializer.decode_u32()?;
        let channel_txn_type = ChannelTransactionType::from_u32(decoded_txn_type);
        match channel_txn_type {
            Some(ChannelTransactionType::Offchain) => {
                let hash_bytes = deserializer.decode_bytes()?;
                let witness_hash = HashValue::from_slice(hash_bytes.as_slice())?;
                let witness_signature = deserializer.decode_struct()?;

                Ok(ChannelTransactionRequestPayload::Offchain {
                    witness_signature,
                    witness_hash,
                })
            }
            Some(ChannelTransactionType::Travel) => {
                let hash_bytes = deserializer.decode_bytes()?;
                let txn_write_set_hash = HashValue::from_slice(hash_bytes.as_slice())?;
                let txn_signature = deserializer.decode_struct()?;
                Ok(ChannelTransactionRequestPayload::Travel {
                    txn_write_set_hash,
                    txn_signature,
                })
            }
            None => Err(format_err!(
                "ParseError: Unable to decode ChannelTransactionType, found {}",
                decoded_txn_type
            )),
        }
    }
}

impl CanonicalSerialize for ChannelTransactionRequest {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        serializer
            .encode_bytes(self.request_id.to_vec().as_slice())?
            .encode_u64(self.version)?
            .encode_struct(&self.operator)?
            .encode_struct(&self.sender)?
            .encode_u64(self.sequence_number)?
            .encode_struct(&self.receiver)?
            .encode_u64(self.channel_sequence_number)?
            .encode_u64(self.expiration_time.as_secs())?
            .encode_struct(&self.payload)?
            .encode_struct(&self.public_key)?
            .encode_vec(&self.args)?
            .encode_u64(self.max_gas_amount)?
            .encode_u64(self.gas_unit_price)?;
        Ok(())
    }
}

impl CanonicalDeserialize for ChannelTransactionRequest {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self>
    where
        Self: Sized,
    {
        let request_id = HashValue::from_slice(deserializer.decode_bytes()?.as_slice())?;
        let version = deserializer.decode_u64()?;
        let operator = deserializer.decode_struct()?;
        let sender = deserializer.decode_struct()?;
        let sequence_number = deserializer.decode_u64()?;
        let receiver = deserializer.decode_struct()?;
        let channel_sequence_number = deserializer.decode_u64()?;
        let expiration_time = Duration::from_secs(deserializer.decode_u64()?);
        let payload = deserializer.decode_struct()?;
        let public_key = deserializer.decode_struct()?;
        let args = deserializer.decode_vec()?;
        let max_gas_amount = deserializer.decode_u64()?;
        let gas_unit_price = deserializer.decode_u64()?;
        Ok(Self {
            request_id,
            version,
            operator,
            sender,
            sequence_number,
            receiver,
            channel_sequence_number,
            expiration_time,
            payload,
            public_key,
            args,
            max_gas_amount,
            gas_unit_price,
        })
    }
}

impl TryFrom<crate::proto::sgtypes::ChannelTransactionRequest> for ChannelTransactionRequest {
    type Error = Error;

    fn try_from(value: crate::proto::sgtypes::ChannelTransactionRequest) -> Result<Self> {
        SimpleDeserializer::deserialize(value.payload.as_slice())
    }
}

impl From<ChannelTransactionRequest> for crate::proto::sgtypes::ChannelTransactionRequest {
    fn from(value: ChannelTransactionRequest) -> Self {
        Self {
            payload: SimpleSerializer::serialize(&value).expect("Serialization should not fail."),
        }
    }
}

impl CanonicalSerialize for ChannelTransactionResponsePayload {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        match self {
            ChannelTransactionResponsePayload::Offchain {
                witness_payload_signature,
            } => {
                serializer
                    .encode_u32(ChannelTransactionType::Offchain as u32)?
                    .encode_bytes(witness_payload_signature.to_bytes().as_ref())?;
            }
            ChannelTransactionResponsePayload::Travel {
                txn_payload_signature,
            } => {
                serializer
                    .encode_u32(ChannelTransactionType::Travel as u32)?
                    .encode_bytes(&txn_payload_signature.to_bytes())?;
            }
        }
        Ok(())
    }
}

impl CanonicalDeserialize for ChannelTransactionResponsePayload {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self>
    where
        Self: Sized,
    {
        let decoded_txn_type = deserializer.decode_u32()?;
        let channel_txn_type = ChannelTransactionType::from_u32(decoded_txn_type);
        match channel_txn_type {
            Some(ChannelTransactionType::Offchain) => {
                let signature = deserializer.decode_struct()?;
                Ok(ChannelTransactionResponsePayload::Offchain {
                    witness_payload_signature: signature,
                })
            }
            Some(ChannelTransactionType::Travel) => {
                let txn_payload_signature = deserializer.decode_struct()?;
                Ok(ChannelTransactionResponsePayload::Travel {
                    txn_payload_signature,
                })
            }
            None => Err(format_err!(
                "ParseError: Unable to decode ChannelTransactionType, found {}",
                decoded_txn_type
            )),
        }
    }
}

impl CanonicalSerialize for ChannelTransactionResponse {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        serializer
            .encode_bytes(self.request_id.to_vec().as_slice())?
            .encode_u64(self.channel_sequence_number)?
            .encode_struct(&self.payload)?
            .encode_bytes(&self.public_key.to_bytes())?;
        Ok(())
    }
}

impl CanonicalDeserialize for ChannelTransactionResponse {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self>
    where
        Self: Sized,
    {
        let request_id = HashValue::from_slice(deserializer.decode_bytes()?.as_slice())?;
        let channel_sequence_number = deserializer.decode_u64()?;
        let payload = deserializer.decode_struct()?;
        let public_key = deserializer.decode_struct()?;
        Ok(Self {
            request_id,
            channel_sequence_number,
            payload,
            public_key,
        })
    }
}

impl TryFrom<crate::proto::sgtypes::ChannelTransactionResponse> for ChannelTransactionResponse {
    type Error = Error;

    fn try_from(value: crate::proto::sgtypes::ChannelTransactionResponse) -> Result<Self> {
        SimpleDeserializer::deserialize(value.payload.as_slice())
    }
}

impl From<ChannelTransactionResponse> for crate::proto::sgtypes::ChannelTransactionResponse {
    fn from(value: ChannelTransactionResponse) -> Self {
        Self {
            payload: SimpleSerializer::serialize(&value).expect("Serialization should not fail."),
        }
    }
}
