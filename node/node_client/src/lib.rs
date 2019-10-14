use failure::{bail, Result};
use grpcio::{ChannelBuilder, Environment};
use star_types::node::{ChannelBalanceRequest, ChannelBalanceResponse, ConnectRequest, ConnectResponse,
                       DepositRequest, DepositResponse, InstallChannelScriptPackageRequest, InstallChannelScriptPackageResponse,
                       OpenChannelRequest, OpenChannelResponse, PayRequest, PayResponse, WithdrawRequest, WithdrawResponse,
                       DeployModuleRequest, DeployModuleResponse, ExecuteScriptRequest, ExecuteScriptResponse};
use star_types::proto::star_types::NodeClient as GrpcNodeClient;
use std::sync::Arc;
use std::convert::TryFrom;

pub struct NodeClient {
    client: GrpcNodeClient,
}

impl NodeClient {
    pub fn new(env: Arc<Environment>, host: &str, port: u16) -> Self {
        let channel = ChannelBuilder::new(env).connect(&format!("{}:{}", host, port));
        let client = GrpcNodeClient::new(channel);
        NodeClient { client }
    }

    pub fn open_channel(&self, request: OpenChannelRequest) -> Result<OpenChannelResponse> {
        let proto_request = request.into();
        match self.client.open_channel(&proto_request) {
            Ok(proto_response) => Ok(OpenChannelResponse::try_from(proto_response)?),
            Err(err) => bail!("GRPC error: {}", err),
        }
    }

    pub fn pay(&self, request: PayRequest) -> Result<PayResponse> {
        let proto_request = request.into();
        match self.client.pay(&proto_request) {
            Ok(proto_response) => Ok(PayResponse::try_from(proto_response)?),
            Err(err) => bail!("GRPC error: {}", err),
        }
    }

    pub fn connect(&self, request: ConnectRequest) -> Result<ConnectResponse> {
        let proto_request = request.into();
        match self.client.connect(&proto_request) {
            Ok(proto_response) => Ok(ConnectResponse::try_from(proto_response)?),
            Err(err) => bail!("GRPC error: {}", err),
        }
    }

    pub fn withdraw(&self, request: WithdrawRequest) -> Result<WithdrawResponse> {
        let proto_request = request.into();
        match self.client.withdraw(&proto_request) {
            Ok(proto_response) => Ok(WithdrawResponse::try_from(proto_response)?),
            Err(err) => bail!("GRPC error: {}", err),
        }
    }

    pub fn channel_balance(
        &self,
        request: ChannelBalanceRequest,
    ) -> Result<ChannelBalanceResponse> {
        let proto_request = request.into();
        match self.client.channel_balance(&proto_request) {
            Ok(proto_response) => Ok(ChannelBalanceResponse::try_from(proto_response)?),
            Err(err) => bail!("GRPC error: {}", err),
        }
    }

    pub fn deposit(&self, request: DepositRequest) -> Result<DepositResponse> {
        let proto_request = request.into();
        match self.client.deposit(&proto_request) {
            Ok(proto_response) => Ok(DepositResponse::try_from(proto_response)?),
            Err(err) => bail!("GRPC error: {}", err),
        }
    }

    pub fn install_channel_script_package(
        &self,
        request: InstallChannelScriptPackageRequest,
    ) -> Result<InstallChannelScriptPackageResponse> {
        let proto_request = request.into();
        match self.client.install_channel_script_package(&proto_request) {
            Ok(proto_response) => Ok(InstallChannelScriptPackageResponse::try_from(
                proto_response,
            )?),
            Err(err) => bail!("GRPC error: {}", err),
        }
    }

    pub fn deploy_module(
        &self,
        request: DeployModuleRequest,
    ) -> Result<DeployModuleResponse> {
        let proto_request = request.into();
        match self.client.deploy_module(&proto_request) {
            Ok(proto_response) => Ok(DeployModuleResponse::try_from(
                proto_response,
            )?),
            Err(err) => bail!("GRPC error: {}", err),
        }
    }

    pub fn execute_script(
        &self,
        request: ExecuteScriptRequest,
    ) -> Result<ExecuteScriptResponse> {
        let proto_request = request.into();
        match self.client.execute_script(&proto_request) {
            Ok(proto_response) => Ok(ExecuteScriptResponse::try_from(
                proto_response,
            )?),
            Err(err) => bail!("GRPC error: {}", err),
        }
    }

}
