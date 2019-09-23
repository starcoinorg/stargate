use types::account_address::AccountAddress;
use failure::prelude::*;
#[cfg(any(test, feature = "testing"))]
use proptest_derive::Arbitrary;
use proto_conv::{FromProto, IntoProto,FromProtoBytes};
use crate::channel_transaction::{ChannelTransactionRequest, ChannelTransactionResponse};
use crypto::ed25519::Ed25519Signature;
use std::{convert::TryFrom, fmt};
use crate::proto::message::{ReceiveSignMessage, ErrorCode};
use parity_multiaddr::Multiaddr;
use crypto::HashValue;
use protobuf::ProtobufEnum;
use crate::sg_error::SgErrorCode;

#[derive(Clone, Debug, Eq, PartialEq)]
//#[ProtoType(crate::proto::message::OpenChannelNodeNegotiateMessage)]
pub struct OpenChannelNodeNegotiateMessage {
    pub raw_negotiate_message : RawNegotiateMessage,
    pub sender_sign: Ed25519Signature,
    pub receiver_sign: Option<Ed25519Signature>,
}

#[derive(Clone, Debug, Eq, PartialEq,FromProto,IntoProto)]
#[ProtoType(crate::proto::message::RawNegotiateMessage)]
pub struct RawNegotiateMessage {
    pub sender_addr: AccountAddress,
    pub resource_type: StructTag,
    pub sender_amount: i64,
    pub receiver_addr: AccountAddress,
    pub receiver_amount: i64,
}

impl RawNegotiateMessage {
    pub fn new(sender_addr:AccountAddress,resource_type:StructTag,sender_amount:i64,receiver_addr:AccountAddress,receiver_amount:i64)->Self{
        RawNegotiateMessage{
            sender_addr,
            resource_type,
            sender_amount,
            receiver_addr,
            receiver_amount,
        }
    }    
}

impl OpenChannelNodeNegotiateMessage {
    pub fn new(raw_negotiate_message:RawNegotiateMessage,sender_sign: Ed25519Signature, receiver_sign: Option<Ed25519Signature>,
    ) -> Self {
        OpenChannelNodeNegotiateMessage {
            raw_negotiate_message,
            sender_sign,
            receiver_sign,
        }
    }
}

impl FromProto for OpenChannelNodeNegotiateMessage {
    type ProtoType = crate::proto::message::OpenChannelNodeNegotiateMessage;

    fn from_proto(mut object: Self::ProtoType) -> Result<Self> {
        let raw = RawNegotiateMessage::from_proto(object.take_raw_message())?;
        let sender_sign =Ed25519Signature::try_from(object.get_sender_sign())?;
        let receiver_sign = if object.has_receiver_sign() {
            Option::Some(Ed25519Signature::try_from(object.get_receiver_sign().get_receiver_sign())?)
        } else {
            Option::None
        };

        Ok(OpenChannelNodeNegotiateMessage::new(raw, sender_sign, receiver_sign))
    }
}

impl IntoProto for OpenChannelNodeNegotiateMessage {
    type ProtoType = crate::proto::message::OpenChannelNodeNegotiateMessage;

    fn into_proto(self) -> Self::ProtoType {
        let mut out = Self::ProtoType::new();
        out.set_raw_message(self.raw_negotiate_message.into_proto());
        out.set_sender_sign(self.sender_sign.to_bytes().to_vec());
        match self.receiver_sign {
            Some(sign) => {
                let mut tmp = ReceiveSignMessage::new();
                tmp.set_receiver_sign(sign.to_bytes().to_vec());
                out.set_receiver_sign(tmp);
            }
            _ => {}
        }

        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq, FromProto, IntoProto)]
#[ProtoType(crate::proto::message::StructTag)]
pub struct StructTag {
    pub account_addr: AccountAddress,
    pub module: String,
    pub name: String,
    pub type_params: Vec<StructTag>,
}

impl StructTag {
    pub fn new(
        account_addr: AccountAddress,
        module: String, name: String, type_params: Vec<StructTag>,
    ) -> Self {
        StructTag {
            account_addr,
            module,
            name,
            type_params,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq,FromProto, IntoProto)]
#[ProtoType(crate::proto::message::ChannelTransactionRequestMessage)]
pub struct ChannelTransactionRequestMessage {
    pub txn_request: ChannelTransactionRequest,
}

impl ChannelTransactionRequestMessage {
    pub fn new(
        txn_request: ChannelTransactionRequest,
    ) -> Self {
        Self{
            txn_request,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq,FromProto, IntoProto)]
#[ProtoType(crate::proto::message::ChannelTransactionResponseMessage)]
pub struct ChannelTransactionResponseMessage {
    pub txn_response: ChannelTransactionResponse,
}

impl ChannelTransactionResponseMessage {
    pub fn new(
        txn_response: ChannelTransactionResponse
    ) -> Self {
        Self{
            txn_response,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressMessage {
    pub addr: AccountAddress,
    pub ip_addr:Multiaddr,
}

impl AddressMessage {
    pub fn new(addr:AccountAddress,ip_addr:Multiaddr)->Self{
        Self{
            addr,
            ip_addr,
        }
    }
}

impl FromProto for AddressMessage {
    type ProtoType = crate::proto::message::AddressMessage;

    fn from_proto(mut object: Self::ProtoType) -> Result<Self> {
        let addr = AccountAddress::from_proto(object.get_addr().to_vec())?;
        let ip_addr = Multiaddr::try_from(object.get_ip_addr().to_vec())?;
        Ok(AddressMessage::new(addr,ip_addr))
    }
}

impl IntoProto for AddressMessage {
    type ProtoType = crate::proto::message::AddressMessage;

    fn into_proto(self) -> Self::ProtoType {
        let mut out = Self::ProtoType::new();
        out.set_addr(self.addr.into_proto());
        out.set_ip_addr(self.ip_addr.to_vec());
        out
    }
}


#[derive(Clone, Debug, Eq, PartialEq)]
#[ProtoType(crate::proto::message::ErrorMessage)]
pub struct ErrorMessage {
    pub raw_transaction_hash: HashValue,
    pub error:SgError,
}

#[derive(Clone, Debug, Eq, PartialEq, Fail)]
#[fail(display = "error code is  {}, error message is {}", error_code,error_message)]
pub struct SgError {
    pub error_code: SgErrorCode,
    pub error_message: String,
}

impl SgError {
    pub fn new(error_code: SgErrorCode,error_message:String)->Self{
        Self{
            error_code,
            error_message,
        }
    }

    pub fn new_channel_not_exist_error(participant: &AccountAddress) -> Self{
        Self {
            error_code:SgErrorCode::CHANNEL_NOT_EXIST,
            error_message: format!("Can not find channel by participant: {}", participant)
        }
    }
}

impl ErrorMessage {
    pub fn new(raw_transaction_hash:HashValue,error:SgError)->Self{
        Self{
            raw_transaction_hash,
            error
        }
    }
}

impl FromProto for ErrorMessage {
    type ProtoType = crate::proto::message::ErrorMessage;

    fn from_proto(mut error_message: Self::ProtoType) -> Result<Self> {
        use crate::proto::message::ErrorCode;

        let raw_transaction_hash=HashValue::from_slice(error_message.get_raw_transaction_hash())?;
        let error_code= SgErrorCode::try_from(error_message.get_error_code())?;
        let error_message = error_message.take_error_message();
        let error = SgError{
            error_code,
            error_message,
        };
        Ok(Self{
            raw_transaction_hash,
            error
        })
    }
}

impl IntoProto for ErrorMessage {
    type ProtoType = crate::proto::message::ErrorMessage;

    fn into_proto(self) -> Self::ProtoType {
        use crate::proto::message::ErrorCode;

        let mut error_message = Self::ProtoType::new();
        error_message.set_raw_transaction_hash(self.raw_transaction_hash.into_proto());
        error_message.set_error_code(self.error.error_code.into_proto());
        error_message.set_error_message(self.error.error_message);
        error_message
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessageType {
    OpenChannelNodeNegotiateMessage,
    ChannelTransactionRequestMessage,
    ChannelTransactionResponseMessage,
    ErrorMessage,
}

impl MessageType {

    pub fn get_type(self)->u16{
        match self {
            MessageType::OpenChannelNodeNegotiateMessage => 1,
            MessageType::ChannelTransactionRequestMessage => 2,
            MessageType::ChannelTransactionResponseMessage => 3,
            MessageType::ErrorMessage => 4,
        }
    }

    pub fn from_type(msg_type:u16)->Result<Self>{
        match msg_type {
            1 => Ok(MessageType::OpenChannelNodeNegotiateMessage),
            2 => Ok(MessageType::ChannelTransactionRequestMessage),
            3 => Ok(MessageType::ChannelTransactionResponseMessage),
            4 => Ok(MessageType::ErrorMessage),
            _ => bail!("no such type"),
        }
    }
}
