use failure::{bail, Result};
use grpcio::{ChannelBuilder, Environment};
use node_proto::{ChannelBalanceRequest, ChannelBalanceResponse, ConnectRequest, ConnectResponse, DepositRequest, DepositResponse, InstallChannelScriptPackageRequest, InstallChannelScriptPackageResponse, OpenChannelRequest, OpenChannelResponse, PayRequest, PayResponse, WithdrawRequest, WithdrawResponse, DeployModuleRequest, DeployModuleResponse};
use proto_conv::{FromProto, IntoProto};
use star_types::proto::node_grpc;
use std::sync::Arc;

pub struct NodeClient {
    client: node_grpc::NodeClient,
}

impl NodeClient {
    pub fn new(env: Arc<Environment>, host: &str, port: u16) -> Self {
        let channel = ChannelBuilder::new(env).connect(&format!("{}:{}", host, port));
        let client = node_grpc::NodeClient::new(channel);
        NodeClient { client }
    }

    pub fn open_channel(&self, request: OpenChannelRequest) -> Result<OpenChannelResponse> {
        let proto_request = request.into_proto();
        match self.client.open_channel(&proto_request) {
            Ok(proto_response) => Ok(OpenChannelResponse::from_proto(proto_response)?),
            Err(err) => bail!("GRPC error: {}", err),
        }
    }

    pub fn pay(&self, request: PayRequest) -> Result<PayResponse> {
        let proto_request = request.into_proto();
        match self.client.pay(&proto_request) {
            Ok(proto_response) => Ok(PayResponse::from_proto(proto_response)?),
            Err(err) => bail!("GRPC error: {}", err),
        }
    }

    pub fn connect(&self, request: ConnectRequest) -> Result<ConnectResponse> {
        let proto_request = request.into_proto();
        match self.client.connect(&proto_request) {
            Ok(proto_response) => Ok(ConnectResponse::from_proto(proto_response)?),
            Err(err) => bail!("GRPC error: {}", err),
        }
    }

    pub fn withdraw(&self, request: WithdrawRequest) -> Result<WithdrawResponse> {
        let proto_request = request.into_proto();
        match self.client.withdraw(&proto_request) {
            Ok(proto_response) => Ok(WithdrawResponse::from_proto(proto_response)?),
            Err(err) => bail!("GRPC error: {}", err),
        }
    }

    pub fn channel_balance(
        &self,
        request: ChannelBalanceRequest,
    ) -> Result<ChannelBalanceResponse> {
        let proto_request = request.into_proto();
        match self.client.channel_balance(&proto_request) {
            Ok(proto_response) => Ok(ChannelBalanceResponse::from_proto(proto_response)?),
            Err(err) => bail!("GRPC error: {}", err),
        }
    }

    pub fn deposit(&self, request: DepositRequest) -> Result<DepositResponse> {
        let proto_request = request.into_proto();
        match self.client.deposit(&proto_request) {
            Ok(proto_response) => Ok(DepositResponse::from_proto(proto_response)?),
            Err(err) => bail!("GRPC error: {}", err),
        }
    }

    pub fn install_channel_script_package(
        &self,
        request: InstallChannelScriptPackageRequest,
    ) -> Result<InstallChannelScriptPackageResponse> {
        let proto_request = request.into_proto();
        match self.client.install_channel_script_package(&proto_request) {
            Ok(proto_response) => Ok(InstallChannelScriptPackageResponse::from_proto(
                proto_response,
            )?),
            Err(err) => bail!("GRPC error: {}", err),
        }
    }

    pub fn deploy_module(
        &self,
        request: DeployModuleRequest,
    ) -> Result<DeployModuleResponse> {
        let proto_request = request.into_proto();
        match self.client.deploy_module(&proto_request) {
            Ok(proto_response) => Ok(DeployModuleResponse::from_proto(
                proto_response,
            )?),
            Err(err) => bail!("GRPC error: {}", err),
        }
    }

}
