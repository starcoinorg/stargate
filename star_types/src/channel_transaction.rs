use core::convert::TryFrom;
use std::fmt::{Display, Formatter};

use num_enum::{IntoPrimitive, TryFromPrimitive};
use protobuf::RepeatedField;
use serde::{Deserialize, Serialize};

use canonical_serialization::{CanonicalDeserialize, CanonicalDeserializer, CanonicalSerialize, CanonicalSerializer, SimpleDeserializer, SimpleSerializer};
use crypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use crypto::HashValue;
use failure::prelude::*;
use proto_conv::{FromProto, IntoProto};
use types::account_address::AccountAddress;
use types::contract_event::ContractEvent;
use types::transaction::{ChannelScriptPayload, ChannelWriteSetPayload, RawTransaction, SignedTransaction, TransactionOutput, TransactionPayload, TransactionStatus, Version};
use types::vm_error::VMStatus;
use types::write_set::WriteSet;

#[derive(
Clone,
Debug,
Eq,
Hash,
PartialEq,
PartialOrd,
Ord,
Serialize,
Deserialize,
)]
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

    pub fn to_string(&self) -> String{
        format!("{}", self)
    }
}

impl CanonicalSerialize for ChannelOp {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        match self {
            ChannelOp::Open => {
                serializer.encode_u32(ChannelOpType::Open as u32)?;
            }
            ChannelOp::Execute { package_name, script_name } => {
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
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self> where
        Self: Sized {
        let decoded_channel_op_type = deserializer.decode_u32()?;
        let channel_op_type = ChannelOpType::from_u32(decoded_channel_op_type);
        match channel_op_type {
            Some(ChannelOpType::Open) => Ok(ChannelOp::Open),
            Some(ChannelOpType::Execute) => {
                let package_name = deserializer.decode_string()?;
                let script_name = deserializer.decode_string()?;
                Ok(ChannelOp::Execute { package_name, script_name })
            }
            Some(ChannelOpType::Close) => Ok(ChannelOp::Close),
            None => {
                Err(format_err!(
                "ParseError: Unable to decode ChannelOpType, found {}",
                decoded_channel_op_type
                ))
            }
        }
    }
}

impl Display for ChannelOp {
    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
        match self {
            ChannelOp::Open => write!(f, "open"),
            ChannelOp::Execute { package_name, script_name } => write!(f, "{}.{}", package_name, script_name),
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
    pub witness_payload: ChannelWriteSetPayload,
    pub witness_signature: Ed25519Signature,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChannelTransactionRequestPayload {
    Offchain(Witness),
    Travel {
        /// The txn output's write_set hash, for receiver to verify the output.
        /// TODO(jole) need hash the whole output?
        txn_write_set_hash: HashValue,
        /// The txn signature, for receiver can build a SignedTransaction with it and RawTransaction , then submit to chain.
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
    /// The sender raw transaction, this txn has not signature
    /// if the txn is travel txn, txn signature at payload, so receiver can submit the txn to chain,
    /// if the txn is offchain txn, receiver can not submit the txn, receiver need to wrap a new txn with witness_payload.
    txn: RawTransaction,
    /// The request payload, depend on txn type.
    payload: ChannelTransactionRequestPayload,
    /// The sender's public key
    public_key: Ed25519PublicKey,
}


impl ChannelTransactionRequest {
    pub fn new(version: Version, operator: ChannelOp, txn: RawTransaction, payload: ChannelTransactionRequestPayload, public_key: Ed25519PublicKey) -> Self {
        let request_id = if let TransactionPayload::ChannelScript(script_payload) = txn.payload() {
            Self::generate_request_id(txn.sender(), script_payload.receiver, script_payload.channel_sequence_number)
        } else {
            panic!("Only support ChannelScript payload.");
        };

        Self {
            request_id,
            version,
            operator,
            txn,
            payload,
            public_key,
        }
    }
    //TODO(jole) should use sequence_number?
    fn generate_request_id(sender: AccountAddress, receiver: AccountAddress, channel_sequence_number: u64) -> HashValue {
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

    pub fn txn(&self) -> &RawTransaction {
        &self.txn
    }

    pub fn payload(&self) -> &ChannelTransactionRequestPayload {
        &self.payload
    }

    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    pub fn txn_payload(&self) -> &ChannelScriptPayload {
        match self.txn.payload() {
            TransactionPayload::ChannelScript(payload) => payload,
            _ => panic!("Only support ChannelScript payload.")
        }
    }

    pub fn is_travel_txn(&self) -> bool {
        match &self.payload {
            ChannelTransactionRequestPayload::Travel { .. } => true,
            _ => false
        }
    }

    pub fn sender(&self) -> AccountAddress {
        self.txn.sender()
    }

    pub fn receiver(&self) -> AccountAddress {
        self.txn_payload().receiver
    }

    pub fn channel_sequence_number(&self) -> u64 {
        self.txn_payload().channel_sequence_number
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelTransactionRequestAndOutput {
    pub request: ChannelTransactionRequest,
    pub output: TransactionOutput,
}

impl ChannelTransactionRequestAndOutput {
    pub fn new(request: ChannelTransactionRequest, output: TransactionOutput) -> Self {
        Self {
            request,
            output,
        }
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChannelTransactionResponsePayload {
    Offchain(Witness),
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
    pub fn new(request_id: HashValue, channel_sequence_number: u64, payload: ChannelTransactionResponsePayload, public_key: Ed25519PublicKey) -> Self {
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
            _ => false
        }
    }
}

impl CanonicalSerialize for Witness {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        serializer.encode_struct(&self.witness_payload)?
            .encode_bytes(&self.witness_signature.to_bytes())?;
        Ok(())
    }
}

impl CanonicalDeserialize for Witness {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self> where
        Self: Sized {
        let witness_payload = deserializer.decode_struct()?;
        let witness_signature_bytes = deserializer.decode_bytes()?;
        Ok(Self {
            witness_payload,
            witness_signature: Ed25519Signature::try_from(witness_signature_bytes.as_slice())?,
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
            ChannelTransactionRequestPayload::Offchain(witness) => {
                serializer.encode_u32(ChannelTransactionType::Offchain as u32)?
                    .encode_struct(witness)?;
            }
            ChannelTransactionRequestPayload::Travel { txn_write_set_hash, txn_signature } => {
                serializer.encode_u32(ChannelTransactionType::Travel as u32)?
                    .encode_bytes(txn_write_set_hash.as_ref())?
                    .encode_bytes(&txn_signature.to_bytes())?;
            }
        }
        Ok(())
    }
}

impl CanonicalDeserialize for ChannelTransactionRequestPayload {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self> where
        Self: Sized {
        let decoded_txn_type = deserializer.decode_u32()?;
        let channel_txn_type = ChannelTransactionType::from_u32(decoded_txn_type);
        match channel_txn_type {
            Some(ChannelTransactionType::Offchain) => {
                let witness = deserializer.decode_struct()?;
                Ok(ChannelTransactionRequestPayload::Offchain(witness))
            }
            Some(ChannelTransactionType::Travel) => {
                let hash_bytes = deserializer.decode_bytes()?;
                let txn_write_set_hash = HashValue::from_slice(hash_bytes.as_slice())?;
                let signature_bytes = deserializer.decode_bytes()?;
                let txn_signature = Ed25519Signature::try_from(signature_bytes.as_slice())?;
                Ok(ChannelTransactionRequestPayload::Travel {
                    txn_write_set_hash,
                    txn_signature,
                })
            }
            None => {
                Err(format_err!(
                "ParseError: Unable to decode ChannelTransactionType, found {}",
                decoded_txn_type
                ))
            }
        }
    }
}

impl CanonicalSerialize for ChannelTransactionRequest {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        serializer.encode_bytes(self.request_id.to_vec().as_slice())?
            .encode_u64(self.version)?
            .encode_struct(&self.operator)?
            .encode_struct(&self.txn)?
            .encode_struct(&self.payload)?
            .encode_bytes(&self.public_key.to_bytes())?;
        Ok(())
    }
}

impl CanonicalDeserialize for ChannelTransactionRequest {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self> where
        Self: Sized {
        let request_id = HashValue::from_slice(deserializer.decode_bytes()?.as_slice())?;
        let version = deserializer.decode_u64()?;
        let operator = deserializer.decode_struct()?;
        let txn = deserializer.decode_struct()?;
        let payload = deserializer.decode_struct()?;
        let public_key_bytes = deserializer.decode_bytes()?;
        Ok(Self {
            request_id,
            version,
            operator,
            txn,
            payload,
            public_key: Ed25519PublicKey::try_from(public_key_bytes.as_slice())?,
        })
    }
}

impl FromProto for ChannelTransactionRequest {
    type ProtoType = crate::proto::channel_transaction::ChannelTransactionRequest;

    fn from_proto(mut object: Self::ProtoType) -> Result<Self> {
        let bytes = object.take_payload();
        Ok(SimpleDeserializer::deserialize(bytes.as_slice())?)
    }
}

impl IntoProto for ChannelTransactionRequest {
    type ProtoType = crate::proto::channel_transaction::ChannelTransactionRequest;

    fn into_proto(self) -> Self::ProtoType {
        let mut out = Self::ProtoType::new();
        out.set_payload(SimpleSerializer::serialize(&self).expect("serialize must success."));
        out
    }
}

impl CanonicalSerialize for ChannelTransactionResponsePayload {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        match self {
            ChannelTransactionResponsePayload::Offchain(witness) => {
                serializer.encode_u32(ChannelTransactionType::Offchain as u32)?
                    .encode_struct(witness)?;
            }
            ChannelTransactionResponsePayload::Travel { txn_payload_signature } => {
                serializer.encode_u32(ChannelTransactionType::Travel as u32)?
                    .encode_bytes(&txn_payload_signature.to_bytes())?;
            }
        }
        Ok(())
    }
}

impl CanonicalDeserialize for ChannelTransactionResponsePayload {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self> where
        Self: Sized {
        let decoded_txn_type = deserializer.decode_u32()?;
        let channel_txn_type = ChannelTransactionType::from_u32(decoded_txn_type);
        match channel_txn_type {
            Some(ChannelTransactionType::Offchain) => {
                let witness = deserializer.decode_struct()?;
                Ok(ChannelTransactionResponsePayload::Offchain(witness))
            }
            Some(ChannelTransactionType::Travel) => {
                let signature_bytes = deserializer.decode_bytes()?;
                let txn_payload_signature = Ed25519Signature::try_from(signature_bytes.as_slice())?;
                Ok(ChannelTransactionResponsePayload::Travel {
                    txn_payload_signature,
                })
            }
            None => {
                Err(format_err!(
                "ParseError: Unable to decode ChannelTransactionType, found {}",
                decoded_txn_type
                ))
            }
        }
    }
}

impl CanonicalSerialize for ChannelTransactionResponse {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        serializer.encode_bytes(self.request_id.to_vec().as_slice())?
            .encode_u64(self.channel_sequence_number)?
            .encode_struct(&self.payload)?
            .encode_bytes(&self.public_key.to_bytes())?;
        Ok(())
    }
}

impl CanonicalDeserialize for ChannelTransactionResponse {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self> where
        Self: Sized {
        let request_id = HashValue::from_slice(deserializer.decode_bytes()?.as_slice())?;
        let channel_sequence_number = deserializer.decode_u64()?;
        let payload = deserializer.decode_struct()?;
        let public_key_bytes = deserializer.decode_bytes()?;
        let public_key = Ed25519PublicKey::try_from(public_key_bytes.as_slice())?;
        Ok(Self {
            request_id,
            channel_sequence_number,
            payload,
            public_key,
        })
    }
}

impl FromProto for ChannelTransactionResponse {
    type ProtoType = crate::proto::channel_transaction::ChannelTransactionResponse;

    fn from_proto(mut object: Self::ProtoType) -> Result<Self> {
        let bytes = object.take_payload();
        Ok(SimpleDeserializer::deserialize(bytes.as_slice())?)
    }
}

impl IntoProto for ChannelTransactionResponse {
    type ProtoType = crate::proto::channel_transaction::ChannelTransactionResponse;

    fn into_proto(self) -> Self::ProtoType {
        let mut out = Self::ProtoType::new();
        out.set_payload(SimpleSerializer::serialize(&self).expect("serialize must success."));
        out
    }
}
