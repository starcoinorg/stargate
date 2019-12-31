// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::channel_transaction::ChannelTransactionRequest;
use crate::s_value::SValue;
use crate::sg_error::SgError;
use anyhow::{bail, format_err, Error, Result};
use bytes::IntoBuf;
use libra_crypto::{
    ed25519::Ed25519Signature,
    hash::{CryptoHash, CryptoHasher, DefaultHasher},
    HashValue,
};
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
    MultiHopChannelTransactionRequest,
    RouterMessage,
}

impl MessageType {
    pub fn get_type(self) -> u16 {
        match self {
            MessageType::OpenChannelNodeNegotiateMessage => 1,
            MessageType::ChannelTransactionRequest => 2,
            MessageType::ChannelTransactionResponse => 3,
            MessageType::ErrorMessage => 4,
            MessageType::MultiHopChannelTransactionRequest => 5,
            MessageType::RouterMessage => 6,
        }
    }

    pub fn from_type(msg_type: u16) -> Result<Self> {
        match msg_type {
            1 => Ok(MessageType::OpenChannelNodeNegotiateMessage),
            2 => Ok(MessageType::ChannelTransactionRequest),
            3 => Ok(MessageType::ChannelTransactionResponse),
            4 => Ok(MessageType::ErrorMessage),
            5 => Ok(MessageType::MultiHopChannelTransactionRequest),
            6 => Ok(MessageType::RouterMessage),
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
    pub total_pay_amount: u64,
}

impl BalanceQueryResponse {
    pub fn new(
        local_addr: AccountAddress,
        remote_addr: AccountAddress,
        local_balance: u64,
        remote_balance: u64,
        total_pay_amount: u64,
    ) -> Self {
        Self {
            local_addr,
            remote_addr,
            local_balance,
            remote_balance,
            total_pay_amount,
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

    pub fn revert(&self) -> Self {
        Self {
            local_addr: self.remote_addr.clone(),
            remote_addr: self.local_addr.clone(),
            local_balance: self.remote_balance,
            remote_balance: self.local_balance,
            total_pay_amount: self.total_pay_amount,
        }
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
            value.total_pay_amount,
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
            total_pay_amount: value.total_pay_amount,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AntQueryMessage {
    pub s_value: SValue,
    pub sender_addr: AccountAddress,
    pub balance_query_response_list: Vec<BalanceQueryResponse>,
}

impl AntQueryMessage {
    pub fn new(
        s_value: SValue,
        sender_addr: AccountAddress,
        balance_query_response_list: Vec<BalanceQueryResponse>,
    ) -> Self {
        Self {
            s_value,
            sender_addr,
            balance_query_response_list,
        }
    }

    pub fn from_proto_bytes<B>(buf: B) -> Result<Self>
    where
        B: IntoBuf,
    {
        crate::proto::sgtypes::AntQueryMessage::decode(buf)?.try_into()
    }

    pub fn into_proto_bytes(self) -> Result<Vec<u8>> {
        Ok(TryInto::<crate::proto::sgtypes::AntQueryMessage>::try_into(self)?.to_vec()?)
    }
}

impl TryFrom<crate::proto::sgtypes::AntQueryMessage> for AntQueryMessage {
    type Error = Error;

    fn try_from(value: crate::proto::sgtypes::AntQueryMessage) -> Result<Self> {
        let balance_query_response_list: Result<Vec<BalanceQueryResponse>> = value
            .balance_query_response_list
            .iter()
            .clone()
            .map(|v| BalanceQueryResponse::try_from(v.clone()))
            .collect();

        Ok(Self::new(
            value.s_value.try_into()?,
            value.sender_addr.try_into()?,
            balance_query_response_list?,
        ))
    }
}

impl From<AntQueryMessage> for crate::proto::sgtypes::AntQueryMessage {
    fn from(value: AntQueryMessage) -> Self {
        Self {
            s_value: value.s_value.to_vec(),
            sender_addr: value.sender_addr.to_vec(),
            balance_query_response_list: value
                .balance_query_response_list
                .iter()
                .cloned()
                .map(|v| v.into())
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NextHop {
    pub remote_addr: AccountAddress,
    pub amount: u64,
}

impl NextHop {
    pub fn new(remote_addr: AccountAddress, amount: u64) -> Self {
        Self {
            remote_addr,
            amount,
        }
    }

    pub fn from_proto_bytes<B>(buf: B) -> Result<Self>
    where
        B: IntoBuf,
    {
        crate::proto::sgtypes::NextHop::decode(buf)?.try_into()
    }

    pub fn into_proto_bytes(self) -> Result<Vec<u8>> {
        Ok(TryInto::<crate::proto::sgtypes::NextHop>::try_into(self)?.to_vec()?)
    }
}

impl TryFrom<crate::proto::sgtypes::NextHop> for NextHop {
    type Error = Error;

    fn try_from(value: crate::proto::sgtypes::NextHop) -> Result<Self> {
        Ok(Self::new(value.remote_addr.try_into()?, value.amount))
    }
}

impl From<NextHop> for crate::proto::sgtypes::NextHop {
    fn from(value: NextHop) -> Self {
        Self {
            remote_addr: value.remote_addr.to_vec(),
            amount: value.amount,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiHopChannelRequest {
    pub request: ChannelTransactionRequest,
    pub hops: Vec<NextHop>,
}

impl MultiHopChannelRequest {
    pub fn new(request: ChannelTransactionRequest, hops: Vec<NextHop>) -> Self {
        Self { request, hops }
    }

    pub fn from_proto_bytes<B>(buf: B) -> Result<Self>
    where
        B: IntoBuf,
    {
        crate::proto::sgtypes::MultiHopChannelRequest::decode(buf)?.try_into()
    }

    pub fn into_proto_bytes(self) -> Result<Vec<u8>> {
        Ok(TryInto::<crate::proto::sgtypes::MultiHopChannelRequest>::try_into(self)?.to_vec()?)
    }
}

impl TryFrom<crate::proto::sgtypes::MultiHopChannelRequest> for MultiHopChannelRequest {
    type Error = Error;

    fn try_from(value: crate::proto::sgtypes::MultiHopChannelRequest) -> Result<Self> {
        let hops: Result<Vec<NextHop>> = value
            .hops
            .iter()
            .clone()
            .map(|v| NextHop::try_from(v.clone()))
            .collect();

        Ok(Self::new(
            value
                .request
                .ok_or_else(|| format_err!("Missing request"))?
                .try_into()?,
            hops?,
        ))
    }
}

impl From<MultiHopChannelRequest> for crate::proto::sgtypes::MultiHopChannelRequest {
    fn from(value: MultiHopChannelRequest) -> Self {
        Self {
            request: Some(value.request.into()),
            hops: value.hops.iter().cloned().map(|v| v.into()).collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExchangeSeedMessageRequest {
    pub sender_seed: u128,
}

impl ExchangeSeedMessageRequest {
    pub fn new(seed: u128) -> Self {
        Self { sender_seed: seed }
    }

    pub fn from_proto_bytes<B>(buf: B) -> Result<Self>
    where
        B: IntoBuf,
    {
        crate::proto::sgtypes::ExchangeSeedMessageRequest::decode(buf)?.try_into()
    }

    pub fn into_proto_bytes(self) -> Result<Vec<u8>> {
        Ok(
            TryInto::<crate::proto::sgtypes::ExchangeSeedMessageRequest>::try_into(self)?
                .to_vec()?,
        )
    }
}

impl TryFrom<crate::proto::sgtypes::ExchangeSeedMessageRequest> for ExchangeSeedMessageRequest {
    type Error = Error;

    fn try_from(value: crate::proto::sgtypes::ExchangeSeedMessageRequest) -> Result<Self> {
        let mut result: [u8; 16] = [0; 16];
        result.copy_from_slice(value.sender_seed.as_ref());
        let seed = u128::from_le_bytes(result);
        Ok(Self::new(seed))
    }
}

impl From<ExchangeSeedMessageRequest> for crate::proto::sgtypes::ExchangeSeedMessageRequest {
    fn from(value: ExchangeSeedMessageRequest) -> Self {
        let mut seed = Vec::new();
        seed.extend_from_slice(&value.sender_seed.to_le_bytes());
        Self { sender_seed: seed }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExchangeSeedMessageResponse {
    pub sender_seed: u128,
    pub receiver_seed: u128,
}

impl ExchangeSeedMessageResponse {
    pub fn new(sender_seed: u128, receiver_seed: u128) -> Self {
        Self {
            sender_seed,
            receiver_seed,
        }
    }

    pub fn from_proto_bytes<B>(buf: B) -> Result<Self>
    where
        B: IntoBuf,
    {
        crate::proto::sgtypes::ExchangeSeedMessageResponse::decode(buf)?.try_into()
    }

    pub fn into_proto_bytes(self) -> Result<Vec<u8>> {
        Ok(
            TryInto::<crate::proto::sgtypes::ExchangeSeedMessageResponse>::try_into(self)?
                .to_vec()?,
        )
    }
}

impl TryFrom<crate::proto::sgtypes::ExchangeSeedMessageResponse> for ExchangeSeedMessageResponse {
    type Error = Error;

    fn try_from(value: crate::proto::sgtypes::ExchangeSeedMessageResponse) -> Result<Self> {
        let mut result: [u8; 16] = [0; 16];
        result.copy_from_slice(value.sender_seed.as_ref());
        let sender_seed = u128::from_le_bytes(result);

        result.copy_from_slice(value.receiver_seed.as_ref());
        let receiver_seed = u128::from_le_bytes(result);

        Ok(Self::new(sender_seed, receiver_seed))
    }
}

impl From<ExchangeSeedMessageResponse> for crate::proto::sgtypes::ExchangeSeedMessageResponse {
    fn from(value: ExchangeSeedMessageResponse) -> Self {
        let mut sender_seed = Vec::new();
        sender_seed.extend_from_slice(&value.sender_seed.to_le_bytes());
        let mut receiver_seed = Vec::new();
        receiver_seed.extend_from_slice(&value.receiver_seed.to_le_bytes());

        Self {
            sender_seed,
            receiver_seed,
        }
    }
}

impl CryptoHash for ExchangeSeedMessageRequest {
    type Hasher = DefaultHasher;

    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::default();
        state.write(&self.sender_seed.to_le_bytes());
        state.finish()
    }
}

impl ExchangeSeedMessageResponse {
    pub fn request_hash(&self) -> HashValue {
        let mut state = DefaultHasher::default();
        state.write(&self.sender_seed.to_le_bytes());
        state.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AntFinalMessage {
    pub r_value: HashValue,
    pub balance_query_response_list: Vec<BalanceQueryResponse>,
}

impl AntFinalMessage {
    pub fn new(r_value: HashValue, balance_query_response_list: Vec<BalanceQueryResponse>) -> Self {
        Self {
            r_value,
            balance_query_response_list,
        }
    }

    pub fn from_proto_bytes<B>(buf: B) -> Result<Self>
    where
        B: IntoBuf,
    {
        crate::proto::sgtypes::AntFinalMessage::decode(buf)?.try_into()
    }

    pub fn into_proto_bytes(self) -> Result<Vec<u8>> {
        Ok(TryInto::<crate::proto::sgtypes::AntFinalMessage>::try_into(self)?.to_vec()?)
    }
}

impl TryFrom<crate::proto::sgtypes::AntFinalMessage> for AntFinalMessage {
    type Error = Error;

    fn try_from(value: crate::proto::sgtypes::AntFinalMessage) -> Result<Self> {
        let balance_query_response_list: Result<Vec<BalanceQueryResponse>> = value
            .balance_query_response_list
            .iter()
            .clone()
            .map(|v| BalanceQueryResponse::try_from(v.clone()))
            .collect();

        Ok(Self::new(
            HashValue::from_slice(&value.r_value)?,
            balance_query_response_list?,
        ))
    }
}

impl From<AntFinalMessage> for crate::proto::sgtypes::AntFinalMessage {
    fn from(value: AntFinalMessage) -> Self {
        Self {
            r_value: value.r_value.to_vec(),
            balance_query_response_list: value
                .balance_query_response_list
                .iter()
                .cloned()
                .map(|v| v.into())
                .collect(),
        }
    }
}

pub enum NodeNetworkMessage {}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Eq, PartialEq)]
pub enum RouterNetworkMessage {
    ExchangeSeedMessageRequest(ExchangeSeedMessageRequest),
    ExchangeSeedMessageResponse(ExchangeSeedMessageResponse),
    AntQueryMessage(AntQueryMessage),
    AntFinalMessage(AntFinalMessage),
    BalanceQueryRequest(BalanceQueryRequest),
    BalanceQueryResponse(BalanceQueryResponse),
}

impl RouterNetworkMessage {
    pub fn from_proto_bytes<B>(buf: B) -> Result<Self>
    where
        B: IntoBuf,
    {
        crate::proto::sgtypes::RouterNetworkMessage::decode(buf)?.try_into()
    }

    pub fn into_proto_bytes(self) -> Result<Vec<u8>> {
        Ok(TryInto::<crate::proto::sgtypes::RouterNetworkMessage>::try_into(self)?.to_vec()?)
    }
}

impl TryFrom<crate::proto::sgtypes::RouterNetworkMessage> for RouterNetworkMessage {
    type Error = anyhow::Error;

    fn try_from(proto: crate::proto::sgtypes::RouterNetworkMessage) -> Result<Self> {
        use crate::proto::sgtypes::router_network_message::RouterMessageItems;

        let item = proto
            .router_message_items
            .ok_or_else(|| format_err!("Missing txn_response_items"))?;

        let response = match item {
            RouterMessageItems::ExchangeSeedRequest(resp) => {
                RouterNetworkMessage::ExchangeSeedMessageRequest(
                    ExchangeSeedMessageRequest::try_from(resp)?,
                )
            }
            RouterMessageItems::ExchangeSeedResponse(resp) => {
                RouterNetworkMessage::ExchangeSeedMessageResponse(
                    ExchangeSeedMessageResponse::try_from(resp)?,
                )
            }
            RouterMessageItems::AntQueryMessage(resp) => {
                RouterNetworkMessage::AntQueryMessage(AntQueryMessage::try_from(resp)?)
            }
            RouterMessageItems::AntFinalMessage(resp) => {
                RouterNetworkMessage::AntFinalMessage(AntFinalMessage::try_from(resp)?)
            }
            RouterMessageItems::BalanceQueryRequest(resp) => {
                RouterNetworkMessage::BalanceQueryRequest(BalanceQueryRequest::try_from(resp)?)
            }
            RouterMessageItems::BalanceQueryResponse(resp) => {
                RouterNetworkMessage::BalanceQueryResponse(BalanceQueryResponse::try_from(resp)?)
            }
        };

        Ok(response)
    }
}

impl From<RouterNetworkMessage> for crate::proto::sgtypes::RouterNetworkMessage {
    fn from(response: RouterNetworkMessage) -> Self {
        use crate::proto::sgtypes::router_network_message::RouterMessageItems;

        let resp = match response {
            RouterNetworkMessage::ExchangeSeedMessageRequest(r) => {
                RouterMessageItems::ExchangeSeedRequest(r.into())
            }
            RouterNetworkMessage::ExchangeSeedMessageResponse(r) => {
                RouterMessageItems::ExchangeSeedResponse(r.into())
            }
            RouterNetworkMessage::AntQueryMessage(r) => {
                RouterMessageItems::AntQueryMessage(r.into())
            }
            RouterNetworkMessage::AntFinalMessage(r) => {
                RouterMessageItems::AntFinalMessage(r.into())
            }
            RouterNetworkMessage::BalanceQueryRequest(r) => {
                RouterMessageItems::BalanceQueryRequest(r.into())
            }
            RouterNetworkMessage::BalanceQueryResponse(r) => {
                RouterMessageItems::BalanceQueryResponse(r.into())
            }
        };

        Self {
            router_message_items: Some(resp),
        }
    }
}
