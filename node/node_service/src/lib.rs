// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use failure::Result;
use futures03::{channel::oneshot, FutureExt, TryFutureExt};
use grpc_helpers::provide_grpc_response;
use grpcio::{EnvBuilder, RpcStatus, RpcStatusCode};
use node_internal::node::Node as Node_Internal;
use node_proto::proto::node::create_node;
use node_proto::{
    ChannelBalanceRequest, ChannelBalanceResponse, DeployModuleRequest, DepositRequest,
    ExecuteScriptRequest, InstallChannelScriptPackageRequest, InstallChannelScriptPackageResponse,
    OpenChannelRequest, PayRequest, QueryTransactionQuest, WithdrawRequest,
};
use sg_config::config::NodeConfig;
use sgchain::star_chain_client::ChainClient;
use sgtypes::signed_channel_transaction::SignedChannelTransaction;
use std::convert::TryFrom;
use std::sync::Arc;

pub fn setup_node_service<C>(config: &NodeConfig, node: Arc<Node_Internal<C>>) -> ::grpcio::Server
where
    C: ChainClient + Clone + Send + Sync + 'static,
{
    let handle = NodeService::new(node);
    let service = create_node(handle);
    ::grpcio::ServerBuilder::new(Arc::new(
        EnvBuilder::new().name_prefix("grpc-node-").build(),
    ))
    .register_service(service)
    .bind(config.rpc_config.address.clone(), config.rpc_config.port)
    .build()
    .expect("Unable to create grpc server")
}

#[derive(Clone)]
pub struct NodeService<C: ChainClient + Clone + Send + Sync + 'static> {
    node: Arc<Node_Internal<C>>,
}

impl<C: ChainClient + Clone + Send + Sync + 'static> NodeService<C> {
    pub fn new(node: Arc<Node_Internal<C>>) -> Self {
        NodeService { node }
    }
}

impl<C: ChainClient + Clone + Send + Sync + 'static> node_proto::proto::node::Node
    for NodeService<C>
{
    fn open_channel(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: node_proto::proto::node::OpenChannelRequest,
        sink: ::grpcio::UnarySink<node_proto::proto::node::OpenChannelResponse>,
    ) {
        let request = OpenChannelRequest::try_from(req).unwrap();
        let rx = self.node.open_channel_oneshot(
            request.remote_addr,
            request.local_amount,
            request.remote_amount,
        );
        //let resp=OpenChannelResponse{}.into();
        //provide_grpc_response(Ok(resp),ctx,sink);
        let fut = process_response(rx, sink);
        ctx.spawn(fut.boxed().unit_error().compat());
    }

    fn pay(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: node_proto::proto::node::PayRequest,
        sink: ::grpcio::UnarySink<node_proto::proto::node::PayResponse>,
    ) {
        let request = PayRequest::try_from(req).unwrap();
        let rx = self
            .node
            .off_chain_pay_oneshot(request.remote_addr, request.amount);
        let fut = process_response(rx, sink);
        ctx.spawn(fut.boxed().unit_error().compat());
    }

    fn deposit(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: node_proto::proto::node::DepositRequest,
        sink: ::grpcio::UnarySink<node_proto::proto::node::DepositResponse>,
    ) {
        let request = DepositRequest::try_from(req).unwrap();
        let rx = self.node.deposit_oneshot(
            request.remote_addr,
            request.local_amount,
            request.remote_amount,
        );
        let fut = process_response(rx, sink);
        ctx.spawn(fut.boxed().unit_error().compat());
    }

    fn withdraw(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: node_proto::proto::node::WithdrawRequest,
        sink: ::grpcio::UnarySink<node_proto::proto::node::WithdrawResponse>,
    ) {
        let request = WithdrawRequest::try_from(req).unwrap();
        let rx = self.node.withdraw_oneshot(
            request.remote_addr,
            request.local_amount,
            request.remote_amount,
        );
        let fut = process_response(rx, sink);
        ctx.spawn(fut.boxed().unit_error().compat());
    }

    fn channel_balance(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: node_proto::proto::node::ChannelBalanceRequest,
        sink: ::grpcio::UnarySink<node_proto::proto::node::ChannelBalanceResponse>,
    ) {
        let request = ChannelBalanceRequest::try_from(req).unwrap();
        let balance = self.node.channel_balance(request.remote_addr).unwrap();
        let resp = ChannelBalanceResponse::new(balance).into();
        provide_grpc_response(Ok(resp), ctx, sink);
    }

    fn install_channel_script_package(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: node_proto::proto::node::InstallChannelScriptPackageRequest,
        sink: ::grpcio::UnarySink<node_proto::proto::node::InstallChannelScriptPackageResponse>,
    ) {
        let request = InstallChannelScriptPackageRequest::try_from(req).unwrap();
        self.node
            .install_package(request.channel_script_package)
            .unwrap();
        let resp = InstallChannelScriptPackageResponse::new().into();
        provide_grpc_response(Ok(resp), ctx, sink);
    }

    fn deploy_module(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: node_proto::proto::node::DeployModuleRequest,
        sink: ::grpcio::UnarySink<node_proto::proto::node::DeployModuleResponse>,
    ) {
        let request = DeployModuleRequest::try_from(req).unwrap();
        let rx = self.node.deploy_package_oneshot(request.module_bytes);
        let fut = process_response(rx, sink);
        ctx.spawn(fut.boxed().unit_error().compat());
    }

    fn execute_script(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: node_proto::proto::node::ExecuteScriptRequest,
        sink: ::grpcio::UnarySink<node_proto::proto::node::ExecuteScriptResponse>,
    ) {
        let request = ExecuteScriptRequest::try_from(req).unwrap();
        let rx = self.node.execute_script_oneshot(
            request.remote_addr,
            request.package_name,
            request.script_name,
            request.args,
        );
        let fut = process_response(rx, sink);
        ctx.spawn(fut.boxed().unit_error().compat());
    }

    fn query_transaction(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: node_proto::proto::node::QueryTransactionQuest,
        sink: ::grpcio::UnarySink<sgtypes::proto::sgtypes::SignedChannelTransaction>,
    ) {
        let request = QueryTransactionQuest::try_from(req).unwrap();
        let rx = self
            .node
            .get_txn_by_channel_sequence_number(
                request.partipant_address,
                request.channel_seq_number,
            )
            .unwrap();
        let resp =
            SignedChannelTransaction::new(rx.raw_tx, rx.sender_signature, rx.receiver_signature)
                .into();
        provide_grpc_response(Ok(resp), ctx, sink);
    }
}

async fn process_response<T, S>(resp: oneshot::Receiver<Result<T>>, sink: grpcio::UnarySink<S>)
where
    S: std::convert::From<T>,
{
    match resp.await {
        Ok(Ok(response)) => {
            sink.success(response.into());
        }
        Ok(Err(err)) => {
            set_failure_message(
                RpcStatusCode::UNKNOWN,
                format!("Failed to process request: {}", err),
                sink,
            );
        }
        Err(oneshot::Canceled) => {
            set_failure_message(
                RpcStatusCode::INTERNAL,
                "Executor Internal error: sender is dropped.".to_string(),
                sink,
            );
        }
    }
}

fn set_failure_message<T>(
    status_code: RpcStatusCode,
    details: String,
    sink: grpcio::UnarySink<T>,
) -> grpcio::UnarySinkResult {
    let status = RpcStatus::new(status_code, Some(details));
    sink.fail(status)
}
