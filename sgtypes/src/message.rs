// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::s_value::SValue;
use crate::sg_error::SgError;
use bytes::IntoBuf;
use failure::prelude::*;
use libra_crypto::{ed25519::Ed25519Signature, HashValue};
use libra_prost_ext::MessageExt;
use libra_types::account_address::AccountAddress;
use parity_multiaddr::Multiaddr;
use prost::Message;
use std::convert::{TryFrom, TryInto};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenChannelNodeNegotiateMessage {
    pub raw_negotiate_message: RawNegotiateMessage,
    pub sender_sign: Ed25519Signature,
    pub receiver_sign: Option<Ed25519Signature>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawNegotiateMessage {
    pub sender_addr: AccountAddress,
    pub resource_type: StructTag,
    pub sender_amount: i64,
    pub receiver_addr: AccountAddress,
    pub receiver_amount: i64,
}

impl RawNegotiateMessage {
    pub fn new(
        sender_addr: AccountAddress,
        resource_type: StructTag,
        sender_amount: i64,
        receiver_addr: AccountAddress,
        receiver_amount: i64,
    ) -> Self {
        RawNegotiateMessage {
            sender_addr,
            resource_type,
            sender_amount,
            receiver_addr,
            receiver_amount,
        }
    }

    pub fn from_proto_bytes<B>(buf: B) -> Result<Self>
    where
        B: IntoBuf,
    {
        crate::proto::sgtypes::RawNegotiateMessage::decode(buf)?.try_into()
    }

    pub fn into_proto_bytes(self) -> Result<Vec<u8>> {
        Ok(TryInto::<crate::proto::sgtypes::RawNegotiateMessage>::try_into(self)?.to_vec()?)
    }
}

impl TryFrom<crate::proto::sgtypes::RawNegotiateMessage> for RawNegotiateMessage {
    type Error = Error;

    fn try_from(value: crate::proto::sgtypes::RawNegotiateMessage) -> Result<Self> {
        Ok(Self::new(
            value.sender_addr.try_into()?,
            value
                .resource_type
                .ok_or_else(|| format_err!("Missing resource_type"))?
                .try_into()?,
            value.sender_amount,
            value.receiver_addr.try_into()?,
            value.receiver_amount,
        ))
    }
}

impl From<RawNegotiateMessage> for crate::proto::sgtypes::RawNegotiateMessage {
    fn from(value: RawNegotiateMessage) -> Self {
        Self {
            sender_addr: value.sender_addr.to_vec(),
            resource_type: Some(value.resource_type.into()),
            sender_amount: value.sender_amount,
            receiver_addr: value.receiver_addr.to_vec(),
            receiver_amount: value.receiver_amount,
        }
    }
}

impl OpenChannelNodeNegotiateMessage {
    pub fn new(
        raw_negotiate_message: RawNegotiateMessage,
        sender_sign: Ed25519Signature,
        receiver_sign: Option<Ed25519Signature>,
    ) -> Self {
        OpenChannelNodeNegotiateMessage {
            raw_negotiate_message,
            sender_sign,
            receiver_sign,
        }
    }

    pub fn from_proto_bytes<B>(buf: B) -> Result<Self>
    where
        B: IntoBuf,
    {
        crate::proto::sgtypes::OpenChannelNodeNegotiateMessage::decode(buf)?.try_into()
    }

    pub fn into_proto_bytes(self) -> Result<Vec<u8>> {
        Ok(
            TryInto::<crate::proto::sgtypes::OpenChannelNodeNegotiateMessage>::try_into(self)?
                .to_vec()?,
        )
    }
}

impl TryFrom<crate::proto::sgtypes::OpenChannelNodeNegotiateMessage>
    for OpenChannelNodeNegotiateMessage
{
    type Error = Error;

    fn try_from(value: crate::proto::sgtypes::OpenChannelNodeNegotiateMessage) -> Result<Self> {
        let raw = value
            .raw_message
            .ok_or_else(|| format_err!("Missing raw_message"))?
            .try_into()?;
        let sender_sign = Ed25519Signature::try_from(value.sender_sign.as_slice())?;
        let receiver_sign = if value.receiver_sign.len() > 0 {
            Option::Some(Ed25519Signature::try_from(value.receiver_sign.as_slice())?)
        } else {
            Option::None
        };

        Ok(OpenChannelNodeNegotiateMessage::new(
            raw,
            sender_sign,
            receiver_sign,
        ))
    }
}

impl From<OpenChannelNodeNegotiateMessage>
    for crate::proto::sgtypes::OpenChannelNodeNegotiateMessage
{
    fn from(value: OpenChannelNodeNegotiateMessage) -> Self {
        Self {
            raw_message: Some(value.raw_negotiate_message.into()),
            sender_sign: value.sender_sign.to_bytes().to_vec(),
            receiver_sign: value
                .receiver_sign
                .map_or(vec![], |sign| sign.to_bytes().to_vec()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructTag {
    pub account_addr: AccountAddress,
    pub module: String,
    pub name: String,
    pub type_params: Vec<StructTag>,
}

impl StructTag {
    pub fn new(
        account_addr: AccountAddress,
        module: String,
        name: String,
        type_params: Vec<StructTag>,
    ) -> Self {
        StructTag {
            account_addr,
            module,
            name,
            type_params,
        }
    }
}

impl TryFrom<crate::proto::sgtypes::StructTag> for StructTag {
    type Error = Error;

    fn try_from(value: crate::proto::sgtypes::StructTag) -> Result<Self> {
        let type_params: Result<Vec<StructTag>> = value
            .type_params
            .iter()
            .cloned()
            .map(|v| Self::try_from(v))
            .collect();
        Ok(Self::new(
            value.account_addr.try_into()?,
            value.module,
            value.name,
            type_params?,
        ))
    }
}

impl From<StructTag> for crate::proto::sgtypes::StructTag {
    fn from(value: StructTag) -> Self {
        Self {
            account_addr: value.account_addr.into(),
            module: value.module,
            name: value.name,
            type_params: value
                .type_params
                .iter()
                .cloned()
                .map(|v| v.into())
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressMessage {
    pub addr: AccountAddress,
    pub ip_addr: Multiaddr,
}

impl AddressMessage {
    pub fn new(addr: AccountAddress, ip_addr: Multiaddr) -> Self {
        Self { addr, ip_addr }
    }
}

impl TryFrom<crate::proto::sgtypes::AddressMessage> for AddressMessage {
    type Error = Error;

    fn try_from(value: crate::proto::sgtypes::AddressMessage) -> Result<Self> {
        Ok(AddressMessage::new(
            value.addr.try_into()?,
            value.ip_addr.to_vec()?.try_into()?,
        ))
    }
}

impl From<AddressMessage> for crate::proto::sgtypes::AddressMessage {
    fn from(value: AddressMessage) -> Self {
        Self {
            addr: value.addr.to_vec(),
            ip_addr: value.ip_addr.to_vec(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErrorMessage {
    pub raw_transaction_hash: HashValue,
    pub error: SgError,
}

impl ErrorMessage {
    pub fn new(raw_transaction_hash: HashValue, error: SgError) -> Self {
        Self {
            raw_transaction_hash,
            error,
        }
    }

    pub fn from_proto_bytes<B>(buf: B) -> Result<Self>
    where
        B: IntoBuf,
    {
        crate::proto::sgtypes::ErrorMessage::decode(buf)?.try_into()
    }

    pub fn into_proto_bytes(self) -> Result<Vec<u8>> {
        Ok(TryInto::<crate::proto::sgtypes::ErrorMessage>::try_into(self)?.to_vec()?)
    }
}

impl TryFrom<crate::proto::sgtypes::ErrorMessage> for ErrorMessage {
    type Error = Error;

    fn try_from(value: crate::proto::sgtypes::ErrorMessage) -> Result<Self> {
        let raw_transaction_hash = HashValue::from_slice(value.raw_transaction_hash.as_slice())?;
        let error = SgError {
            error_code: value.error_code.try_into()?,
            error_message: value.error_message,
        };
        Ok(Self {
            raw_transaction_hash,
            error,
        })
    }
}

impl From<ErrorMessage> for crate::proto::sgtypes::ErrorMessage {
    fn from(value: ErrorMessage) -> Self {
        Self {
            raw_transaction_hash: value.raw_transaction_hash.to_vec(),
            error_code: value.error.error_code.into(),
            error_message: value.error.error_message,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessageType {
    OpenChannelNodeNegotiateMessage,
    ChannelTransactionRequest,
    ChannelTransactionResponse,
    ErrorMessage,
    BalanceQueryResponse,
    BalanceQueryRequest,
}

impl MessageType {
    pub fn get_type(self) -> u16 {
        match self {
            MessageType::OpenChannelNodeNegotiateMessage => 1,
            MessageType::ChannelTransactionRequest => 2,
            MessageType::ChannelTransactionResponse => 3,
            MessageType::ErrorMessage => 4,
            MessageType::BalanceQueryResponse => 5,
            MessageType::BalanceQueryRequest => 6,
        }
    }

    pub fn from_type(msg_type: u16) -> Result<Self> {
        match msg_type {
            1 => Ok(MessageType::OpenChannelNodeNegotiateMessage),
            2 => Ok(MessageType::ChannelTransactionRequest),
            3 => Ok(MessageType::ChannelTransactionResponse),
            4 => Ok(MessageType::ErrorMessage),
            5 => Ok(MessageType::BalanceQueryResponse),
            6 => Ok(MessageType::BalanceQueryRequest),
            _ => bail!("no such type"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BalanceQueryRequest {
    pub local_addr: AccountAddress,
    pub remote_addr: AccountAddress,
}

impl BalanceQueryRequest {
    pub fn new(local_addr: AccountAddress, remote_addr: AccountAddress) -> Self {
        Self {
            local_addr,
            remote_addr,
        }
    }

    pub fn from_proto_bytes<B>(buf: B) -> Result<Self>
    where
        B: IntoBuf,
    {
        crate::proto::sgtypes::BalanceQueryRequest::decode(buf)?.try_into()
    }

    pub fn into_proto_bytes(self) -> Result<Vec<u8>> {
        Ok(TryInto::<crate::proto::sgtypes::BalanceQueryRequest>::try_into(self)?.to_vec()?)
    }
}

impl TryFrom<crate::proto::sgtypes::BalanceQueryRequest> for BalanceQueryRequest {
    type Error = Error;

    fn try_from(value: crate::proto::sgtypes::BalanceQueryRequest) -> Result<Self> {
        Ok(Self::new(
            value.local_addr.try_into()?,
            value.remote_addr.try_into()?,
        ))
    }
}

impl From<BalanceQueryRequest> for crate::proto::sgtypes::BalanceQueryRequest {
    fn from(value: BalanceQueryRequest) -> Self {
        Self {
            local_addr: value.local_addr.to_vec(),
            remote_addr: value.remote_addr.to_vec(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BalanceQueryResponse {
    pub local_addr: AccountAddress,
    pub remote_addr: AccountAddress,
    pub local_balance: u64,
    pub remote_balance: u64,
}

impl BalanceQueryResponse {
    pub fn new(
        local_addr: AccountAddress,
        remote_addr: AccountAddress,
        local_balance: u64,
        remote_balance: u64,
    ) -> Self {
        Self {
            local_addr,
            remote_addr,
            local_balance,
            remote_balance,
        }
    }

    pub fn from_proto_bytes<B>(buf: B) -> Result<Self>
    where
        B: IntoBuf,
    {
        crate::proto::sgtypes::BalanceQueryResponse::decode(buf)?.try_into()
    }

    pub fn into_proto_bytes(self) -> Result<Vec<u8>> {
        Ok(TryInto::<crate::proto::sgtypes::BalanceQueryResponse>::try_into(self)?.to_vec()?)
    }
}

impl TryFrom<crate::proto::sgtypes::BalanceQueryResponse> for BalanceQueryResponse {
    type Error = Error;

    fn try_from(value: crate::proto::sgtypes::BalanceQueryResponse) -> Result<Self> {
        Ok(Self::new(
            value.local_addr.try_into()?,
            value.remote_addr.try_into()?,
            value.local_balance,
            value.remote_balance,
        ))
    }
}

impl From<BalanceQueryResponse> for crate::proto::sgtypes::BalanceQueryResponse {
    fn from(value: BalanceQueryResponse) -> Self {
        Self {
            local_addr: value.local_addr.to_vec(),
            remote_addr: value.remote_addr.to_vec(),
            local_balance: value.local_balance,
            remote_balance: value.remote_balance,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VertexInfo {
    pub addr: AccountAddress,
}

impl VertexInfo {
    pub fn new(addr: AccountAddress) -> Self {
        Self { addr }
    }

    pub fn from_proto_bytes<B>(buf: B) -> Result<Self>
    where
        B: IntoBuf,
    {
        crate::proto::sgtypes::VertexInfo::decode(buf)?.try_into()
    }

    pub fn into_proto_bytes(self) -> Result<Vec<u8>> {
        Ok(TryInto::<crate::proto::sgtypes::VertexInfo>::try_into(self)?.to_vec()?)
    }
}

impl TryFrom<crate::proto::sgtypes::VertexInfo> for VertexInfo {
    type Error = Error;

    fn try_from(value: crate::proto::sgtypes::VertexInfo) -> Result<Self> {
        Ok(Self::new(value.addr.try_into()?))
    }
}

impl From<VertexInfo> for crate::proto::sgtypes::VertexInfo {
    fn from(value: VertexInfo) -> Self {
        Self {
            addr: value.addr.to_vec(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AntMessage {
    pub s_value: SValue,
    pub vertex_list: Vec<VertexInfo>,
}

impl AntMessage {
    pub fn new(s_value: SValue, vertex_list: Vec<VertexInfo>) -> Self {
        Self {
            s_value,
            vertex_list,
        }
    }

    pub fn from_proto_bytes<B>(buf: B) -> Result<Self>
    where
        B: IntoBuf,
    {
        crate::proto::sgtypes::AntMessage::decode(buf)?.try_into()
    }

    pub fn into_proto_bytes(self) -> Result<Vec<u8>> {
        Ok(TryInto::<crate::proto::sgtypes::AntMessage>::try_into(self)?.to_vec()?)
    }
}

impl TryFrom<crate::proto::sgtypes::AntMessage> for AntMessage {
    type Error = Error;

    fn try_from(value: crate::proto::sgtypes::AntMessage) -> Result<Self> {
        let vertex_list: Result<Vec<VertexInfo>> = value
            .vertex_list
            .iter()
            .clone()
            .map(|v| VertexInfo::try_from(v.clone()))
            .collect();

        Ok(Self::new(value.s_value.try_into()?, vertex_list?))
    }
}

impl From<AntMessage> for crate::proto::sgtypes::AntMessage {
    fn from(value: AntMessage) -> Self {
        Self {
            s_value: value.s_value.to_vec(),
            vertex_list: value
                .vertex_list
                .iter()
                .cloned()
                .map(|v| v.into())
                .collect(),
        }
    }
}

pub enum NodeNetworkMessage {
    BalanceQueryResponseEnum(BalanceQueryResponse),
}
