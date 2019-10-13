//#[cfg(test)]
//mod protobuf_conversion_test;

use failure::prelude::*;
#[cfg(any(test, feature = "testing"))]
use proptest_derive::Arbitrary;
use proto_conv::{FromProto, IntoProto};
use star_types::script_package::ChannelScriptPackage;
use libra_types::account_address::AccountAddress;
use protobuf::RepeatedField;
use libra_types::transaction::SignedTransactionWithProof;
use crypto::HashValue;

#[derive(Clone, Debug, Eq, PartialEq, FromProto, IntoProto)]
#[ProtoType(star_types::proto::node::OpenChannelRequest)]
#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
pub struct OpenChannelRequest {
    pub remote_addr: AccountAddress,
    pub local_amount: u64,
    pub remote_amount: u64,
}

impl OpenChannelRequest {
    pub fn new(remote_addr: AccountAddress, local_amount: u64, remote_amount: u64) -> Self {
        Self {
            remote_addr,
            local_amount,
            remote_amount,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
pub struct OpenChannelResponse {}

impl OpenChannelResponse {
    pub fn new() -> Self {
        OpenChannelResponse {}
    }
}

impl FromProto for OpenChannelResponse {
    type ProtoType = star_types::proto::node::OpenChannelResponse;

    fn from_proto(mut object: Self::ProtoType) -> Result<Self> {
        Ok(OpenChannelResponse {})
    }
}

impl IntoProto for OpenChannelResponse {
    type ProtoType = star_types::proto::node::OpenChannelResponse;

    fn into_proto(self) -> Self::ProtoType {
        let mut out = Self::ProtoType::new();
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq, FromProto, IntoProto)]
#[ProtoType(star_types::proto::node::PayRequest)]
#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
pub struct PayRequest {
    pub remote_addr: AccountAddress,
    pub amount: u64,
}

impl PayRequest {
    pub fn new(remote_addr: AccountAddress, amount: u64) -> Self {
        PayRequest {
            remote_addr,
            amount,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
pub struct PayResponse {}

impl PayResponse {
    pub fn new() -> Self {
        PayResponse {}
    }
}

impl FromProto for PayResponse {
    type ProtoType = star_types::proto::node::PayResponse;

    fn from_proto(mut object: Self::ProtoType) -> Result<Self> {
        Ok(PayResponse {})
    }
}

impl IntoProto for PayResponse {
    type ProtoType = star_types::proto::node::PayResponse;

    fn into_proto(self) -> Self::ProtoType {
        let mut out = Self::ProtoType::new();
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq, FromProto, IntoProto)]
#[ProtoType(star_types::proto::node::ConnectRequest)]
#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
pub struct ConnectRequest {
    pub remote_addr: AccountAddress,
    pub remote_ip: String,
}

impl ConnectRequest {
    pub fn new(remote_addr: AccountAddress, remote_ip: String) -> Self {
        Self {
            remote_addr,
            remote_ip,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, FromProto, IntoProto)]
#[ProtoType(star_types::proto::node::ConnectResponse)]
#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
pub struct ConnectResponse {}

impl ConnectResponse {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Clone, Debug, Eq, PartialEq, FromProto, IntoProto)]
#[ProtoType(star_types::proto::node::DepositRequest)]
#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
pub struct DepositRequest {
    pub remote_addr: AccountAddress,
    pub local_amount: u64,
    pub remote_amount: u64,
}

impl DepositRequest {
    pub fn new(remote_addr: AccountAddress, local_amount: u64, remote_amount: u64) -> Self {
        Self {
            remote_addr,
            local_amount,
            remote_amount,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, FromProto, IntoProto)]
#[ProtoType(star_types::proto::node::DepositResponse)]
#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
pub struct DepositResponse {}

impl DepositResponse {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Clone, Debug, Eq, PartialEq, FromProto, IntoProto)]
#[ProtoType(star_types::proto::node::WithdrawRequest)]
#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
pub struct WithdrawRequest {
    pub remote_addr: AccountAddress,
    pub local_amount: u64,
    pub remote_amount: u64,
}

impl WithdrawRequest {
    pub fn new(remote_addr: AccountAddress, local_amount: u64, remote_amount: u64) -> Self {
        Self {
            remote_addr,
            local_amount,
            remote_amount,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, FromProto, IntoProto)]
#[ProtoType(star_types::proto::node::WithdrawResponse)]
#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
pub struct WithdrawResponse {}

impl WithdrawResponse {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Clone, Debug, Eq, PartialEq, FromProto, IntoProto)]
#[ProtoType(star_types::proto::node::ChannelBalanceRequest)]
#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
pub struct ChannelBalanceRequest {
    pub remote_addr: AccountAddress,
}

impl ChannelBalanceRequest {
    pub fn new(remote_addr: AccountAddress) -> Self {
        Self { remote_addr }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, FromProto, IntoProto)]
#[ProtoType(star_types::proto::node::ChannelBalanceResponse)]
#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
pub struct ChannelBalanceResponse {
    pub balance: u64,
}

impl ChannelBalanceResponse {
    pub fn new(balance: u64) -> Self {
        Self { balance }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, FromProto, IntoProto)]
#[ProtoType(star_types::proto::node::InstallChannelScriptPackageRequest)]
pub struct InstallChannelScriptPackageRequest {
    pub channel_script_package: ChannelScriptPackage,
}

impl InstallChannelScriptPackageRequest{
    pub fn new(channel_script_package: ChannelScriptPackage) -> Self {
        Self {channel_script_package}
    }
}

#[derive(Clone, Debug, Eq, PartialEq, FromProto, IntoProto)]
#[ProtoType(star_types::proto::node::InstallChannelScriptPackageResponse)]
#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
pub struct InstallChannelScriptPackageResponse {}

impl InstallChannelScriptPackageResponse {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Clone, Debug, Eq, PartialEq, FromProto, IntoProto)]
#[ProtoType(star_types::proto::node::DeployModuleRequest)]
pub struct DeployModuleRequest {
    pub module_bytes: Vec<u8>,
}

impl DeployModuleRequest{
    pub fn new(module_bytes: Vec<u8>) -> Self {
        Self {module_bytes}
    }
}


#[derive(Clone, Debug, Eq, PartialEq, FromProto, IntoProto)]
#[ProtoType(star_types::proto::node::DeployModuleResponse)]
#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
pub struct DeployModuleResponse {
    pub transaction_with_proof :SignedTransactionWithProof,
}

impl DeployModuleResponse {
    pub fn new( transaction_with_proof :SignedTransactionWithProof) -> Self {
        Self {transaction_with_proof}
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteScriptRequest{
    pub remote_addr:AccountAddress,
    pub package_name:String,
    pub script_name:String,
    pub args:Vec<Vec<u8>>,
}

impl ExecuteScriptRequest {
    pub fn new(remote_addr:AccountAddress,package_name:String, script_name:String, args:Vec<Vec<u8>>)->Self{
        Self{
            remote_addr,
            package_name,
            script_name,
            args,
        }
    }
}

impl FromProto for ExecuteScriptRequest {
    type ProtoType = star_types::proto::node::ExecuteScriptRequest;

    fn from_proto(mut object: Self::ProtoType) -> Result<Self> {
        Ok(ExecuteScriptRequest{
            remote_addr:AccountAddress::from_proto(object.take_remote_addr())?,
            package_name:object.take_package_name(),
            script_name:object.take_script_name(),
            args:object.args.to_vec(),
        })
    }
}

impl IntoProto for ExecuteScriptRequest {
    type ProtoType = star_types::proto::node::ExecuteScriptRequest;

    fn into_proto(self) -> Self::ProtoType {
        let mut out = Self::ProtoType::new();
        out.set_remote_addr(self.remote_addr.to_vec());
        out.set_package_name(self.package_name);
        out.set_script_name(self.script_name);
        out.set_args(RepeatedField::from_vec(self.args));
        out
    }
}


#[derive(Clone, Debug, Eq, PartialEq, FromProto, IntoProto)]
#[ProtoType(star_types::proto::node::ExecuteScriptResponse)]
#[cfg_attr(any(test, feature = "testing"), derive(Arbitrary))]
pub struct ExecuteScriptResponse{
    pub hash_value:HashValue,
}

impl ExecuteScriptResponse{
    pub fn new(hash_value:HashValue)->Self{
        Self{hash_value}
    }
}