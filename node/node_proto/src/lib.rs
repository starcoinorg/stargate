pub mod proto;

//#[cfg(test)]
//mod protobuf_conversion_test;

use types::account_address::AccountAddress;
use failure::prelude::*;
#[cfg(any(test, feature = "testing"))]
use proptest_derive::Arbitrary;
use proto_conv::{FromProto, IntoProto};

#[derive(Clone, Debug, Eq, PartialEq, FromProto, IntoProto)]
#[ProtoType(crate::proto::node::OpenChannelRequest)]
#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
pub struct OpenChannelRequest {
    pub remote_addr: AccountAddress,
}

impl OpenChannelRequest {
    pub fn new(
        remote_addr: AccountAddress,
    ) -> Self {
        OpenChannelRequest {
            remote_addr,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
pub struct OpenChannelResponse {
}

impl OpenChannelResponse {
    pub fn new(
    ) -> Self {
        OpenChannelResponse {
        }
    }

}

impl FromProto for OpenChannelResponse {
    type ProtoType = crate::proto::node::OpenChannelResponse;

    fn from_proto(mut object: Self::ProtoType) -> Result<Self> {
        Ok(OpenChannelResponse {
        })
    }
}

impl IntoProto for OpenChannelResponse {
    type ProtoType = crate::proto::node::OpenChannelResponse;

    fn into_proto(self) -> Self::ProtoType {
        let mut out = Self::ProtoType::new();        
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq, FromProto, IntoProto)]
#[ProtoType(crate::proto::node::PayRequest)]
#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
pub struct PayRequest {
    pub remote_addr: AccountAddress,
}

impl PayRequest {
    pub fn new(
        remote_addr: AccountAddress,
    ) -> Self {
        PayRequest {
            remote_addr,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
pub struct PayResponse {
}

impl PayResponse {
    pub fn new(
    ) -> Self {
        PayResponse {
        }
    }

}

impl FromProto for PayResponse {
    type ProtoType = crate::proto::node::PayResponse;

    fn from_proto(mut object: Self::ProtoType) -> Result<Self> {
        Ok(PayResponse {
        })
    }
}

impl IntoProto for PayResponse {
    type ProtoType = crate::proto::node::PayResponse;

    fn into_proto(self) -> Self::ProtoType {
        let mut out = Self::ProtoType::new();        
        out
    }
}
