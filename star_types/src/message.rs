use types::account_address::AccountAddress;
use failure::prelude::*;
#[cfg(any(test, feature = "testing"))]
use proptest_derive::Arbitrary;
use proto_conv::{FromProto, IntoProto};
use crate::offchain_transaction::OffChainTransaction;
use crypto::ed25519::Ed25519Signature;
use std::convert::{TryFrom};
use crate::proto::message::ReceiveSignMessage;
use parity_multiaddr::Multiaddr;

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
#[ProtoType(crate::proto::message::OffChainPayMessage)]
pub struct OffChainPayMessage {
    pub transaction: OffChainTransaction,
}

impl OffChainPayMessage {
    pub fn new(
        transaction: OffChainTransaction,
    ) -> Self {
        OffChainPayMessage {
            transaction,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq,FromProto, IntoProto)]
#[ProtoType(crate::proto::message::OffChainPayMessage)]
pub struct OpenChannelTransactionMessage {
    pub transaction: OffChainTransaction,
}

impl OpenChannelTransactionMessage {
    pub fn new(
        transaction: OffChainTransaction,
    ) -> Self {
        OpenChannelTransactionMessage {
            transaction,
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
pub enum MessageType {
    OpenChannelNodeNegotiateMessage,
    OpenChannelTransactionMessage,
    OffChainPayMessage,
    AddressMessage,
}

impl MessageType {

    pub fn get_type(self)->u16{
        match self {
            MessageType::OpenChannelNodeNegotiateMessage => 1,
            MessageType::OpenChannelTransactionMessage => 2,
            MessageType::OffChainPayMessage => 3,
            MessageType::AddressMessage => 4,
        }
    }

    pub fn from_type(msg_type:u16)->Result<Self>{
        match msg_type {
            1 => Ok(MessageType::OpenChannelNodeNegotiateMessage),
            2 => Ok(MessageType::OpenChannelTransactionMessage),
            3 => Ok(MessageType::OffChainPayMessage),
            4 => Ok(MessageType::AddressMessage),
            _ => bail!("no such type"),
        }
    }
}