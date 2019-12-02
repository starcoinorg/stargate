// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

//#[cfg(test)]
//mod protobuf_conversion_test;

use failure::prelude::*;
use libra_crypto::HashValue;
use libra_types::account_address::AccountAddress;
use libra_types::transaction::TransactionWithProof;
use sgtypes::channel_transaction::ChannelTransaction;
use sgtypes::script_package::ChannelScriptPackage;
use std::convert::{TryFrom, TryInto};

pub mod proto;

#[derive(Clone, Debug, Eq, PartialEq)]
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

impl TryFrom<crate::proto::node::OpenChannelRequest> for OpenChannelRequest {
    type Error = Error;

    fn try_from(value: crate::proto::node::OpenChannelRequest) -> Result<Self> {
        Ok(Self {
            remote_addr: value.remote_addr.try_into()?,
            local_amount: value.local_amount,
            remote_amount: value.remote_amount,
        })
    }
}

impl From<OpenChannelRequest> for crate::proto::node::OpenChannelRequest {
    fn from(value: OpenChannelRequest) -> Self {
        Self {
            remote_addr: value.remote_addr.into(),
            local_amount: value.local_amount,
            remote_amount: value.remote_amount,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenChannelResponse {}

impl OpenChannelResponse {
    pub fn new() -> Self {
        OpenChannelResponse {}
    }
}

impl TryFrom<crate::proto::node::OpenChannelResponse> for OpenChannelResponse {
    type Error = Error;

    fn try_from(_value: crate::proto::node::OpenChannelResponse) -> Result<Self> {
        Ok(Self::new())
    }
}

impl From<OpenChannelResponse> for crate::proto::node::OpenChannelResponse {
    fn from(_value: OpenChannelResponse) -> Self {
        Self::default()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

impl TryFrom<crate::proto::node::PayRequest> for PayRequest {
    type Error = Error;

    fn try_from(value: crate::proto::node::PayRequest) -> Result<Self> {
        Ok(Self {
            remote_addr: value.remote_addr.try_into()?,
            amount: value.amount,
        })
    }
}

impl From<PayRequest> for crate::proto::node::PayRequest {
    fn from(value: PayRequest) -> Self {
        Self {
            remote_addr: value.remote_addr.into(),
            amount: value.amount,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayResponse {}

impl PayResponse {
    pub fn new() -> Self {
        PayResponse {}
    }
}

impl TryFrom<crate::proto::node::PayResponse> for PayResponse {
    type Error = Error;

    fn try_from(_value: crate::proto::node::PayResponse) -> Result<Self> {
        Ok(Self::new())
    }
}

impl From<PayResponse> for crate::proto::node::PayResponse {
    fn from(_value: PayResponse) -> Self {
        Self::default()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositRequest {
    pub remote_addr: AccountAddress,
    pub local_amount: u64,
}

impl DepositRequest {
    pub fn new(remote_addr: AccountAddress, local_amount: u64) -> Self {
        Self {
            remote_addr,
            local_amount,
        }
    }
}

impl TryFrom<crate::proto::node::DepositRequest> for DepositRequest {
    type Error = Error;

    fn try_from(value: crate::proto::node::DepositRequest) -> Result<Self> {
        Ok(Self {
            remote_addr: value.remote_addr.try_into()?,
            local_amount: value.local_amount,
        })
    }
}

impl From<DepositRequest> for crate::proto::node::DepositRequest {
    fn from(value: DepositRequest) -> Self {
        Self {
            remote_addr: value.remote_addr.into(),
            local_amount: value.local_amount,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositResponse {}

impl DepositResponse {
    pub fn new() -> Self {
        Self {}
    }
}

impl TryFrom<crate::proto::node::DepositResponse> for DepositResponse {
    type Error = Error;

    fn try_from(_value: crate::proto::node::DepositResponse) -> Result<Self> {
        Ok(Self::new())
    }
}

impl From<DepositResponse> for crate::proto::node::DepositResponse {
    fn from(_value: DepositResponse) -> Self {
        Self::default()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawRequest {
    pub remote_addr: AccountAddress,
    pub local_amount: u64,
}

impl WithdrawRequest {
    pub fn new(remote_addr: AccountAddress, local_amount: u64) -> Self {
        Self {
            remote_addr,
            local_amount,
        }
    }
}

impl TryFrom<crate::proto::node::WithdrawRequest> for WithdrawRequest {
    type Error = Error;

    fn try_from(value: crate::proto::node::WithdrawRequest) -> Result<Self> {
        Ok(Self {
            remote_addr: value.remote_addr.try_into()?,
            local_amount: value.local_amount,
        })
    }
}

impl From<WithdrawRequest> for crate::proto::node::WithdrawRequest {
    fn from(value: WithdrawRequest) -> Self {
        Self {
            remote_addr: value.remote_addr.into(),
            local_amount: value.local_amount,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawResponse {}

impl WithdrawResponse {
    pub fn new() -> Self {
        Self {}
    }
}

impl TryFrom<crate::proto::node::WithdrawResponse> for WithdrawResponse {
    type Error = Error;

    fn try_from(_value: crate::proto::node::WithdrawResponse) -> Result<Self> {
        Ok(Self::new())
    }
}

impl From<WithdrawResponse> for crate::proto::node::WithdrawResponse {
    fn from(_value: WithdrawResponse) -> Self {
        Self::default()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelBalanceRequest {
    pub remote_addr: AccountAddress,
}

impl ChannelBalanceRequest {
    pub fn new(remote_addr: AccountAddress) -> Self {
        Self { remote_addr }
    }
}

impl TryFrom<crate::proto::node::ChannelBalanceRequest> for ChannelBalanceRequest {
    type Error = Error;

    fn try_from(value: crate::proto::node::ChannelBalanceRequest) -> Result<Self> {
        Ok(Self {
            remote_addr: value.remote_addr.try_into()?,
        })
    }
}

impl From<ChannelBalanceRequest> for crate::proto::node::ChannelBalanceRequest {
    fn from(value: ChannelBalanceRequest) -> Self {
        Self {
            remote_addr: value.remote_addr.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelBalanceResponse {
    pub balance: u64,
}

impl ChannelBalanceResponse {
    pub fn new(balance: u64) -> Self {
        Self { balance }
    }
}

impl TryFrom<crate::proto::node::ChannelBalanceResponse> for ChannelBalanceResponse {
    type Error = Error;

    fn try_from(value: crate::proto::node::ChannelBalanceResponse) -> Result<Self> {
        Ok(Self {
            balance: value.balance,
        })
    }
}

impl From<ChannelBalanceResponse> for crate::proto::node::ChannelBalanceResponse {
    fn from(value: ChannelBalanceResponse) -> Self {
        Self {
            balance: value.balance,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallChannelScriptPackageRequest {
    pub channel_script_package: ChannelScriptPackage,
}

impl InstallChannelScriptPackageRequest {
    pub fn new(channel_script_package: ChannelScriptPackage) -> Self {
        Self {
            channel_script_package,
        }
    }
}

impl TryFrom<crate::proto::node::InstallChannelScriptPackageRequest>
    for InstallChannelScriptPackageRequest
{
    type Error = Error;

    fn try_from(value: crate::proto::node::InstallChannelScriptPackageRequest) -> Result<Self> {
        Ok(Self {
            channel_script_package: value
                .channel_script_package
                .ok_or_else(|| format_err!("Missing channel_script_package"))?
                .try_into()?,
        })
    }
}

impl From<InstallChannelScriptPackageRequest>
    for crate::proto::node::InstallChannelScriptPackageRequest
{
    fn from(value: InstallChannelScriptPackageRequest) -> Self {
        Self {
            channel_script_package: Some(value.channel_script_package.into()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallChannelScriptPackageResponse {}

impl InstallChannelScriptPackageResponse {
    pub fn new() -> Self {
        Self {}
    }
}

impl TryFrom<crate::proto::node::InstallChannelScriptPackageResponse>
    for InstallChannelScriptPackageResponse
{
    type Error = Error;

    fn try_from(_value: crate::proto::node::InstallChannelScriptPackageResponse) -> Result<Self> {
        Ok(Self::new())
    }
}

impl From<InstallChannelScriptPackageResponse>
    for crate::proto::node::InstallChannelScriptPackageResponse
{
    fn from(_value: InstallChannelScriptPackageResponse) -> Self {
        Self::default()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeployModuleRequest {
    pub module_bytes: Vec<u8>,
}

impl DeployModuleRequest {
    pub fn new(module_bytes: Vec<u8>) -> Self {
        Self { module_bytes }
    }
}

impl TryFrom<crate::proto::node::DeployModuleRequest> for DeployModuleRequest {
    type Error = Error;

    fn try_from(value: crate::proto::node::DeployModuleRequest) -> Result<Self> {
        Ok(Self {
            module_bytes: value.module_bytes,
        })
    }
}

impl From<DeployModuleRequest> for crate::proto::node::DeployModuleRequest {
    fn from(value: DeployModuleRequest) -> Self {
        Self {
            module_bytes: value.module_bytes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeployModuleResponse {
    pub transaction_with_proof: TransactionWithProof,
}

impl DeployModuleResponse {
    pub fn new(transaction_with_proof: TransactionWithProof) -> Self {
        Self {
            transaction_with_proof,
        }
    }
}

impl TryFrom<crate::proto::node::DeployModuleResponse> for DeployModuleResponse {
    type Error = Error;

    fn try_from(value: crate::proto::node::DeployModuleResponse) -> Result<Self> {
        Ok(Self {
            transaction_with_proof: value
                .transaction_with_proof
                .ok_or_else(|| format_err!("Missing transaction_with_proof"))?
                .try_into()?,
        })
    }
}

impl From<DeployModuleResponse> for crate::proto::node::DeployModuleResponse {
    fn from(value: DeployModuleResponse) -> Self {
        Self {
            transaction_with_proof: Some(value.transaction_with_proof.into()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteScriptRequest {
    pub remote_addr: AccountAddress,
    pub package_name: String,
    pub script_name: String,
    pub args: Vec<Vec<u8>>,
}

impl ExecuteScriptRequest {
    pub fn new(
        remote_addr: AccountAddress,
        package_name: String,
        script_name: String,
        args: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            remote_addr,
            package_name,
            script_name,
            args,
        }
    }
}

impl TryFrom<crate::proto::node::ExecuteScriptRequest> for ExecuteScriptRequest {
    type Error = Error;

    fn try_from(value: crate::proto::node::ExecuteScriptRequest) -> Result<Self> {
        Ok(Self {
            remote_addr: value.remote_addr.try_into()?,
            package_name: value.package_name,
            script_name: value.script_name,
            args: value.args.to_vec(),
        })
    }
}

impl From<ExecuteScriptRequest> for crate::proto::node::ExecuteScriptRequest {
    fn from(value: ExecuteScriptRequest) -> Self {
        Self {
            remote_addr: value.remote_addr.into(),
            package_name: value.package_name,
            script_name: value.script_name,
            args: value.args,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteScriptResponse {
    pub channel_seq_number: u64,
}

impl ExecuteScriptResponse {
    pub fn new(channel_seq_number: u64) -> Self {
        Self { channel_seq_number }
    }
}

impl TryFrom<crate::proto::node::ExecuteScriptResponse> for ExecuteScriptResponse {
    type Error = Error;

    fn try_from(value: crate::proto::node::ExecuteScriptResponse) -> Result<Self> {
        Ok(Self::new(value.channel_sequence_number))
    }
}

impl From<ExecuteScriptResponse> for crate::proto::node::ExecuteScriptResponse {
    fn from(value: ExecuteScriptResponse) -> Self {
        Self {
            channel_sequence_number: value.channel_seq_number,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryTransactionQuest {
    pub participant_address: AccountAddress,
    pub channel_seq_number: u64,
}

impl QueryTransactionQuest {
    pub fn new(participant_address: AccountAddress, channel_seq_number: u64) -> Self {
        Self {
            participant_address,
            channel_seq_number,
        }
    }
}

impl TryFrom<crate::proto::node::QueryTransactionQuest> for QueryTransactionQuest {
    type Error = Error;

    fn try_from(request: crate::proto::node::QueryTransactionQuest) -> Result<Self> {
        let participant_address = AccountAddress::try_from(request.participant_address)?;
        Ok(Self::new(participant_address, request.channel_seq_number))
    }
}

impl From<QueryTransactionQuest> for crate::proto::node::QueryTransactionQuest {
    fn from(request: QueryTransactionQuest) -> Self {
        Self {
            participant_address: request.participant_address.to_vec(),
            channel_seq_number: request.channel_seq_number,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetChannelTransactionProposalResponse {
    pub channel_transaction: Option<ChannelTransaction>,
}

impl GetChannelTransactionProposalResponse {
    pub fn new(channel_transaction: Option<ChannelTransaction>) -> Self {
        Self {
            channel_transaction,
        }
    }
}

impl TryFrom<crate::proto::node::GetChannelTransactionProposalResponse>
    for GetChannelTransactionProposalResponse
{
    type Error = Error;

    fn try_from(
        request: crate::proto::node::GetChannelTransactionProposalResponse,
    ) -> Result<Self> {
        match request.channel_transaction {
            Some(t) => {
                return Ok(Self::new(Some(t.try_into()?)));
            }
            None => {
                return Ok(Self::new(None));
            }
        }
    }
}

impl From<GetChannelTransactionProposalResponse>
    for crate::proto::node::GetChannelTransactionProposalResponse
{
    fn from(request: GetChannelTransactionProposalResponse) -> Self {
        match request.channel_transaction {
            Some(t) => Self {
                channel_transaction: Some(t.into()),
            },
            None => Self {
                channel_transaction: None,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelTransactionProposalRequest {
    pub participant_address: AccountAddress,
    pub transaction_hash: HashValue,
    pub approve: bool,
}

impl ChannelTransactionProposalRequest {
    pub fn new(
        participant_address: AccountAddress,
        transaction_hash: HashValue,
        approve: bool,
    ) -> Self {
        Self {
            participant_address,
            transaction_hash,
            approve,
        }
    }
}

impl TryFrom<crate::proto::node::ChannelTransactionProposalRequest>
    for ChannelTransactionProposalRequest
{
    type Error = Error;

    fn try_from(request: crate::proto::node::ChannelTransactionProposalRequest) -> Result<Self> {
        let participant_address = AccountAddress::try_from(request.participant_address)?;
        Ok(Self::new(
            participant_address,
            HashValue::from_slice(&request.transaction_hash)?,
            request.approve,
        ))
    }
}

impl From<ChannelTransactionProposalRequest>
    for crate::proto::node::ChannelTransactionProposalRequest
{
    fn from(request: ChannelTransactionProposalRequest) -> Self {
        Self {
            participant_address: request.participant_address.to_vec(),
            transaction_hash: request.transaction_hash.to_vec(),
            approve: request.approve,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmptyResponse {}

impl EmptyResponse {
    pub fn new() -> Self {
        Self {}
    }
}

impl TryFrom<crate::proto::node::EmptyResponse> for EmptyResponse {
    type Error = Error;

    fn try_from(_value: crate::proto::node::EmptyResponse) -> Result<Self> {
        Ok(Self::new())
    }
}

impl From<EmptyResponse> for crate::proto::node::EmptyResponse {
    fn from(_value: EmptyResponse) -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_compile() {
        println!("it work");
    }
}
