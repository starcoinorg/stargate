// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::channel_transaction_sigs::ChannelTransactionSigs;
use crate::hash::ChannelTransactionHasher;
use canonical_serialization::{
    CanonicalDeserialize, CanonicalDeserializer, CanonicalSerialize, CanonicalSerializer,
    SimpleDeserializer, SimpleSerializer,
};
use crypto::hash::{CryptoHash, CryptoHasher};
use crypto::HashValue;
use failure::prelude::*;
use libra_types::transaction::{ChannelTransactionPayload, TransactionArgument, Version};
use libra_types::{account_address::AccountAddress, transaction::TransactionOutput};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::{
    convert::TryFrom,
    fmt::{Display, Formatter},
};

/// sender (init channel transaction):
/// 1. constructs ChannelTransaction, (sign on it if offchain)
/// 2. from  ChannelTransaction, construct Libra RawTransaction, (sign on it of onchain),
/// 3. execute it, get the channel writeset payload, and sign on it.
/// 4. construct a SignedChannelTransaction, and send it to receiver.
///
/// receiver (verify channel transaction and sign on it):
/// 1. check the signature on ChannelTransaction,
/// 2. constructs the raw transaction, (mock sender signature on raw tx if offchain), execute it, get the writeset.
/// 3. check the sender's signature on writeset payload.
/// 4. sign on transaction and the writeset payload.
/// 5. construct a SignedChannelTransaction, and send it to sender.
///
/// sender/reciever (apply channel tx):
/// 1. check signature again if sender.
/// 2. if onchian, sender constructs signed transaction of onchain, submit it to onchain.
///    receiver waits the onchain tx.
/// 3. if offchain, sender and receiver apply the tx to their local storage.  

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChannelTransaction {
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

    args: Vec<TransactionArgument>,
}

impl ChannelTransaction {
    pub fn new(
        version: Version,
        operator: ChannelOp,
        sender: AccountAddress,
        sequence_number: u64,
        receiver: AccountAddress,
        channel_sequence_number: u64,
        expiration_time: Duration,
        args: Vec<TransactionArgument>,
    ) -> Self {
        Self {
            version,
            operator,
            sender,
            sequence_number,
            receiver,
            channel_sequence_number,
            expiration_time,
            args,
        }
    }
}

impl ChannelTransaction {
    pub fn version(&self) -> Version {
        self.version
    }

    pub fn operator(&self) -> &ChannelOp {
        &self.operator
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
}

impl CryptoHash for ChannelTransaction {
    type Hasher = ChannelTransactionHasher;

    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::default();
        state.write(
            SimpleSerializer::<Vec<u8>>::serialize(self)
                .expect("Failed to serialize ChannelTransaction")
                .as_slice(),
        );
        state.finish()
    }
}

impl CanonicalSerialize for ChannelTransaction {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        serializer
            .encode_u64(self.version)?
            .encode_struct(&self.operator)?
            .encode_struct(&self.sender)?
            .encode_u64(self.sequence_number)?
            .encode_struct(&self.receiver)?
            .encode_u64(self.channel_sequence_number)?
            .encode_u64(self.expiration_time.as_secs())?
            .encode_vec(&self.args)?;

        Ok(())
    }
}

impl CanonicalDeserialize for ChannelTransaction {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self>
    where
        Self: Sized,
    {
        let version = deserializer.decode_u64()?;
        let operator = deserializer.decode_struct()?;
        let sender = deserializer.decode_struct()?;
        let sequence_number = deserializer.decode_u64()?;
        let receiver = deserializer.decode_struct()?;
        let channel_sequence_number = deserializer.decode_u64()?;
        let expiration_time = Duration::from_secs(deserializer.decode_u64()?);
        let args = deserializer.decode_vec()?;
        Ok(ChannelTransaction::new(
            version,
            operator,
            sender,
            sequence_number,
            receiver,
            channel_sequence_number,
            expiration_time,
            args,
        ))
    }
}

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
pub struct ChannelTransactionRequest {
    /// The id of request
    request_id: HashValue,
    channel_txn: ChannelTransaction,
    channel_txn_sigs: ChannelTransactionSigs,
    travel: bool,
}

impl ChannelTransactionRequest {
    pub fn new(
        channel_txn: ChannelTransaction,
        channel_txn_sigs: ChannelTransactionSigs,
        travel: bool,
    ) -> Self {
        let sender = channel_txn.sender();
        let receiver = channel_txn.receiver();
        let channel_sequence_number = channel_txn.channel_sequence_number();
        let request_id = Self::generate_request_id(sender, receiver, channel_sequence_number);
        Self {
            request_id,
            channel_txn,
            channel_txn_sigs,
            travel,
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
    pub fn channel_txn(&self) -> &ChannelTransaction {
        &self.channel_txn
    }
    pub fn channel_txn_sigs(&self) -> &ChannelTransactionSigs {
        &self.channel_txn_sigs
    }

    pub fn sender(&self) -> AccountAddress {
        self.channel_txn.sender()
    }
    pub fn receiver(&self) -> AccountAddress {
        self.channel_txn.receiver()
    }

    pub fn is_travel_txn(&self) -> bool {
        self.travel
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelTransactionRequestAndOutput {
    pub request: ChannelTransactionRequest,
    pub output: TransactionOutput,
    pub verified_participant_witness_payload: Option<ChannelTransactionPayload>,
}

impl ChannelTransactionRequestAndOutput {
    pub fn new(
        request: ChannelTransactionRequest,
        output: TransactionOutput,
        verified_participant_witness_payload: Option<ChannelTransactionPayload>,
    ) -> Self {
        Self {
            request,
            output,
            verified_participant_witness_payload,
        }
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChannelTransactionResponse {
    request_id: HashValue,
    channel_txn_sigs: ChannelTransactionSigs,
}

impl ChannelTransactionResponse {
    pub fn new(request_id: HashValue, channel_txn_sigs: ChannelTransactionSigs) -> Self {
        Self {
            request_id,
            channel_txn_sigs,
        }
    }

    pub fn request_id(&self) -> HashValue {
        self.request_id
    }
    pub fn channel_txn_sigs(&self) -> &ChannelTransactionSigs {
        &self.channel_txn_sigs
    }
}

impl CanonicalSerialize for ChannelTransactionRequest {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        serializer
            .encode_bytes(self.request_id.to_vec().as_slice())?
            .encode_struct(&self.channel_txn)?
            .encode_struct(&self.channel_txn_sigs)?
            .encode_bool(self.travel)?;
        Ok(())
    }
}

impl CanonicalDeserialize for ChannelTransactionRequest {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self>
    where
        Self: Sized,
    {
        let request_id = HashValue::from_slice(deserializer.decode_bytes()?.as_slice())?;
        let channel_txn = deserializer.decode_struct()?;
        let channel_txn_sigs = deserializer.decode_struct()?;
        let travel = deserializer.decode_bool()?;
        Ok(Self {
            request_id,
            channel_txn,
            channel_txn_sigs,
            travel,
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

impl CanonicalSerialize for ChannelTransactionResponse {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        serializer
            .encode_bytes(self.request_id.to_vec().as_slice())?
            .encode_struct(&self.channel_txn_sigs)?;
        Ok(())
    }
}

impl CanonicalDeserialize for ChannelTransactionResponse {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self>
    where
        Self: Sized,
    {
        let request_id = HashValue::from_slice(deserializer.decode_bytes()?.as_slice())?;
        let channel_txn_sigs = deserializer.decode_struct()?;
        Ok(Self {
            request_id,
            channel_txn_sigs,
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
