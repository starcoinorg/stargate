// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::channel_transaction_sigs::ChannelTransactionSigs;
use crate::hash::ChannelTransactionHasher;
use bytes::IntoBuf;
use failure::prelude::*;
use libra_crypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use libra_crypto::hash::{CryptoHash, CryptoHasher};
use libra_crypto::HashValue;
use libra_prost_ext::MessageExt;
use libra_types::transaction::{ChannelTransactionPayload, TransactionArgument, Version};
use libra_types::{account_address::AccountAddress, transaction::TransactionOutput};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::hash::Hash;
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
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize, CryptoHasher)]
pub struct ChannelTransaction {
    /// The global status version on this tx executed.
    version: Version,
    /// channel address to execute txn.
    channel_address: AccountAddress,
    /// Sequence number of this channel.
    channel_sequence_number: u64,
    /// channel action
    operator: ChannelOp,
    args: Vec<TransactionArgument>,
    /// txn proposer
    proposer: AccountAddress,
    /// Sequence number of this transaction corresponding to proposer's account.
    sequence_number: u64,
    /// The txn expiration time
    expiration_time: Duration,
}

impl ChannelTransaction {
    pub fn new(
        version: Version,
        channel_address: AccountAddress,
        channel_sequence_number: u64,
        operator: ChannelOp,
        args: Vec<TransactionArgument>,
        proposer: AccountAddress,
        proposer_sequence_number: u64,
        expiration_time: Duration,
    ) -> Self {
        Self {
            version,
            channel_address,
            channel_sequence_number,
            operator,
            args,
            proposer,
            sequence_number: proposer_sequence_number,
            expiration_time,
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
    pub fn channel_address(&self) -> AccountAddress {
        self.channel_address
    }
    pub fn proposer(&self) -> AccountAddress {
        self.proposer
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

impl TryFrom<crate::proto::sgtypes::ChannelTransaction> for ChannelTransaction {
    type Error = Error;

    fn try_from(value: crate::proto::sgtypes::ChannelTransaction) -> Result<Self> {
        let version = value.version;
        let operator = ChannelOp::try_from(value.operator.unwrap())?;
        let sender = AccountAddress::try_from(value.sender)?;
        let sequence_number = value.sequence_number;
        let receiver = AccountAddress::try_from(value.receiver)?;
        let channel_sequence_number = value.channel_sequence_number;
        let expiration_time = Duration::from_secs(value.expiration_time);
        let args = value
            .args
            .into_iter()
            .map(TransactionArgument::try_from)
            .collect::<Result<Vec<_>>>()?;
        Ok(ChannelTransaction {
            version,
            operator,
            sender,
            sequence_number,
            receiver,
            channel_sequence_number,
            expiration_time,
            args,
        })
    }
}

impl From<ChannelTransaction> for crate::proto::sgtypes::ChannelTransaction {
    fn from(value: ChannelTransaction) -> Self {
        Self {
            version: value.version.to_owned(),
            operator: Some(value.operator.into()),
            sender: value.sender.into(),
            sequence_number: value.sequence_number.into(),
            receiver: value.receiver.into(),
            channel_sequence_number: value.channel_sequence_number,
            expiration_time: value.expiration_time.as_secs(),
            args: value.args.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum ChannelOp {
    Open,
    Execute {
        package_name: String,
        script_name: String,
    },
    Action {
        module_address: AccountAddress,
        module_name: String,
        function_name: String,
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

impl Display for ChannelOp {
    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
        match self {
            ChannelOp::Open => write!(f, "open"),
            ChannelOp::Execute {
                package_name,
                script_name,
            } => write!(f, "{}.{}", package_name, script_name),
            ChannelOp::Action {
                module_address,
                module_name,
                function_name,
            } => write!(f, "{}.{}.{}", module_address, module_name, function_name),
            ChannelOp::Close => write!(f, "close"),
        }
    }
}

impl std::error::Error for ChannelOp {}

impl TryFrom<crate::proto::sgtypes::ChannelOp> for ChannelOp {
    type Error = Error;

    fn try_from(proto: crate::proto::sgtypes::ChannelOp) -> Result<Self> {
        use crate::proto::sgtypes::ChannelOpType as ProtoChannelOpType;
        let ret = match proto.op_type() {
            ProtoChannelOpType::Open => ChannelOp::Open,
            ProtoChannelOpType::Execute => {
                let package_name = proto.package_name;
                let script_name = proto.script_name;
                ChannelOp::Execute {
                    package_name,
                    script_name,
                }
            }
            ProtoChannelOpType::Close => ChannelOp::Close,
        };
        Ok(ret)
    }
}

impl From<ChannelOp> for crate::proto::sgtypes::ChannelOp {
    fn from(cop: ChannelOp) -> Self {
        use crate::proto::sgtypes::ChannelOpType as ProtoChannelOpType;
        let mut channel_op = Self::default();

        match cop {
            ChannelOp::Open => {
                channel_op.set_op_type(ProtoChannelOpType::Open);
            }
            ChannelOp::Execute {
                package_name,
                script_name,
            } => {
                channel_op.package_name = package_name;
                channel_op.script_name = script_name;
                channel_op.set_op_type(ProtoChannelOpType::Execute);
            }
            ChannelOp::Close => {
                channel_op.set_op_type(ProtoChannelOpType::Close);
            }
        };
        channel_op
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChannelTransactionRequest {
    proposal: ChannelTransactionProposal,
    channel_txn_sigs: ChannelTransactionSigs,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChannelTransactionProposal {
    pub channel_txn: ChannelTransaction,
    pub proposer_public_key: Ed25519PublicKey,
    pub proposer_signature: Ed25519Signature,
}

impl ChannelTransactionProposal {
    pub fn new(
        channel_txn: ChannelTransaction,
        proposer_public_key: Ed25519PublicKey,
        proposer_signature: Ed25519Signature,
    ) -> Self {
        Self {
            channel_txn,
            proposer_public_key,
            proposer_signature,
        }
    }
}

impl ChannelTransactionRequest {
    pub fn new(
        proposal: ChannelTransactionProposal,
        channel_txn_sigs: ChannelTransactionSigs,
    ) -> Self {
        Self {
            proposal,
            channel_txn_sigs,
        }
    }

    pub fn request_id(&self) -> HashValue {
        self.channel_txn().hash()
    }
    pub fn channel_txn(&self) -> &ChannelTransaction {
        &self.channel_txn
    }
    pub fn channel_txn_sigs(&self) -> &ChannelTransactionSigs {
        &self.channel_txn_sigs
    }

    pub fn proposer(&self) -> AccountAddress {
        self.channel_txn.proposer()
    }

    pub fn channel_address(&self) -> AccountAddress {
        self.channel_txn.channel_address()
    }

    pub fn is_travel_txn(&self) -> bool {
        unimplemented!()
    }

    pub fn from_proto_bytes<B>(buf: B) -> Result<Self>
    where
        B: IntoBuf,
    {
        crate::proto::sgtypes::ChannelTransactionRequest::decode(buf)?.try_into()
    }

    pub fn into_proto_bytes(self) -> Result<Vec<u8>> {
        Ok(
            TryInto::<crate::proto::sgtypes::ChannelTransactionRequest>::try_into(self)?
                .to_vec()?,
        )
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

    pub fn from_proto_bytes<B>(buf: B) -> Result<Self>
    where
        B: IntoBuf,
    {
        crate::proto::sgtypes::ChannelTransactionResponse::decode(buf)?.try_into()
    }

    pub fn into_proto_bytes(self) -> Result<Vec<u8>> {
        Ok(
            TryInto::<crate::proto::sgtypes::ChannelTransactionResponse>::try_into(self)?
                .to_vec()?,
        )
    }
}

impl TryFrom<crate::proto::sgtypes::ChannelTransactionRequest> for ChannelTransactionRequest {
    type Error = Error;

    fn try_from(value: crate::proto::sgtypes::ChannelTransactionRequest) -> Result<Self> {
        let request_id = HashValue::from_slice(&value.request_id)?;
        let channel_txn = ChannelTransaction::try_from(value.channel_txn.unwrap())?;
        let channel_txn_sigs = ChannelTransactionSigs::try_from(value.channel_txn_sigs.unwrap())?;
        let travel = value.travel;
        Ok(ChannelTransactionRequest {
            request_id,
            channel_txn,
            channel_txn_sigs,
            travel,
        })
    }
}

impl From<ChannelTransactionRequest> for crate::proto::sgtypes::ChannelTransactionRequest {
    fn from(value: ChannelTransactionRequest) -> Self {
        Self {
            request_id: value.request_id.to_vec(),
            channel_txn: Some(value.channel_txn.into()),
            channel_txn_sigs: Some(value.channel_txn_sigs.into()),
            travel: value.travel,
        }
    }
}

impl TryFrom<crate::proto::sgtypes::ChannelTransactionResponse> for ChannelTransactionResponse {
    type Error = Error;

    fn try_from(response: crate::proto::sgtypes::ChannelTransactionResponse) -> Result<Self> {
        let request_id = HashValue::from_slice(&response.request_id)?;
        let channel_txn_sigs =
            ChannelTransactionSigs::try_from(response.channel_txn_sigs.unwrap())?;
        Ok(Self {
            request_id,
            channel_txn_sigs,
        })
    }
}

impl From<ChannelTransactionResponse> for crate::proto::sgtypes::ChannelTransactionResponse {
    fn from(response: ChannelTransactionResponse) -> Self {
        Self {
            request_id: response.request_id.to_vec(),
            channel_txn_sigs: Some(response.channel_txn_sigs.into()),
        }
    }
}
