use types::account_address::AccountAddress;
use failure::prelude::*;
#[cfg(any(test, feature = "testing"))]
use proptest_derive::Arbitrary;
use proto_conv::{FromProto, IntoProto};
use crate::offchain_transaction::OffChainTransaction;
use nextgen_crypto::ed25519::{Ed25519Signature};
use core::convert::TryFrom;

#[derive(Clone, Debug, Eq, PartialEq)]
//#[ProtoType(crate::proto::message::OpenChannelNodeNegotiateMessage)]
pub struct OpenChannelNodeNegotiateMessage {
    pub sender_addr: AccountAddress,
    pub sender_resource_type :StructTag ,
    pub sender_amount :i64 ,
    pub receiver_addr:AccountAddress,
    pub receiver_resource_type: StructTag,
    pub receiver_amount: i64 ,
    pub sender_sign :Ed25519Signature ,
    pub receiver_sign :Ed25519Signature ,
}

impl OpenChannelNodeNegotiateMessage {
    pub fn new(
        sender_addr: AccountAddress,sender_resource_type :StructTag ,sender_amount :i64 ,
        receiver_addr:AccountAddress,receiver_resource_type: StructTag,receiver_amount: i64 ,
        sender_sign :Ed25519Signature ,receiver_sign :Ed25519Signature ,
    ) -> Self {
        OpenChannelNodeNegotiateMessage {
            sender_addr,sender_resource_type,sender_amount,
            receiver_addr,receiver_resource_type,receiver_amount,
            sender_sign,receiver_sign,            
        }
    }
}

impl FromProto for OpenChannelNodeNegotiateMessage {
    type ProtoType = crate::proto::message::OpenChannelNodeNegotiateMessage;

    fn from_proto(mut object: Self::ProtoType) -> Result<Self> {
        let sender_addr = AccountAddress::from_proto(object.get_sender_addr().to_vec()).unwrap();
        let sender_resource_type = StructTag::from_proto(object.take_sender_resource_type()).unwrap();
        let receiver_addr =  AccountAddress::from_proto(object.get_receiver_addr().to_vec()).unwrap();
        let receiver_resource_type = StructTag::from_proto(object.take_receiver_resource_type()).unwrap();
        let sender_sign = Ed25519Signature::try_from(object.get_sender_sign()).unwrap();
        let receiver_sign = Ed25519Signature::try_from(object.get_receiver_sign()).unwrap();
        Ok(OpenChannelNodeNegotiateMessage::new(sender_addr,sender_resource_type, object.get_sender_amount(),
            receiver_addr, receiver_resource_type, object.get_receiver_amount(), sender_sign,receiver_sign))
    }
}

impl IntoProto for OpenChannelNodeNegotiateMessage {
    type ProtoType = crate::proto::message::OpenChannelNodeNegotiateMessage;

    fn into_proto(self) -> Self::ProtoType {
        let mut out = Self::ProtoType::new();
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq, FromProto, IntoProto)]
#[ProtoType(crate::proto::message::StructTag)]
pub struct StructTag {
    pub account_addr: AccountAddress,
    pub module:String,
    pub name:String,
    pub type_params:Vec<StructTag>,
}

impl StructTag {
    pub fn new(
        account_addr: AccountAddress,
        module:String,name:String,type_params:Vec<StructTag>
    ) -> Self {
        StructTag {
            account_addr,
            module,
            name,type_params
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
