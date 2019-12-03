// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use failure::Result;
use futures03::{channel::oneshot, FutureExt, TryFutureExt};
use grpc_helpers::provide_grpc_response;
use grpcio::{EnvBuilder, RpcStatus, RpcStatusCode};
use node_internal::node::Node as Node_Internal;
use node_proto::proto::node::create_node;
use node_proto::{
    ChannelBalanceRequest, ChannelBalanceResponse, ChannelTransactionProposalRequest,
    DeployModuleRequest, DepositRequest, ExecuteScriptRequest, InstallChannelScriptPackageRequest,
    InstallChannelScriptPackageResponse, OpenChannelRequest, PayRequest, QueryTransactionQuest,
    WithdrawRequest,
};
use sg_config::config::NodeConfig;
use std::convert::TryFrom;
use std::sync::Arc;

pub fn setup_node_service(config: &NodeConfig, node: Arc<Node_Internal>) -> ::grpcio::Server {
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
pub struct NodeService {
    node: Arc<Node_Internal>,
}

impl NodeService {
    pub fn new(node: Arc<Node_Internal>) -> Self {
        NodeService { node }
    }
}

impl node_proto::proto::node::Node for NodeService {
    fn open_channel(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: node_proto::proto::node::OpenChannelRequest,
        sink: ::grpcio::UnarySink<node_proto::proto::node::OpenChannelResponse>,
    ) {
        let request = OpenChannelRequest::try_from(req).unwrap();
        let node = self.node.clone();
        let f = async move {
            let rx = node
                .open_channel_oneshot(
                    request.remote_addr,
                    request.local_amount,
                    request.remote_amount,
                )
                .await;
            process_response(rx, sink).await;
        };
        ctx.spawn(f.boxed().unit_error().compat());
    }

    fn pay(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: node_proto::proto::node::PayRequest,
        sink: ::grpcio::UnarySink<node_proto::proto::node::PayResponse>,
    ) {
        let request = PayRequest::try_from(req).unwrap();
        let node = self.node.clone();
        let f = async move {
            let rx = node
                .off_chain_pay_oneshot(request.remote_addr, request.amount)
                .await;
            process_response(rx, sink).await;
        };
        ctx.spawn(f.boxed().unit_error().compat());
    }

    fn deposit(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: node_proto::proto::node::DepositRequest,
        sink: ::grpcio::UnarySink<node_proto::proto::node::DepositResponse>,
    ) {
        let request = DepositRequest::try_from(req).unwrap();
        let node = self.node.clone();
        let f = async move {
            let rx = node
                .deposit_oneshot(request.remote_addr, request.local_amount)
                .await;
            process_response(rx, sink).await;
        };
        ctx.spawn(f.boxed().unit_error().compat());
    }

    fn withdraw(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: node_proto::proto::node::WithdrawRequest,
        sink: ::grpcio::UnarySink<node_proto::proto::node::WithdrawResponse>,
    ) {
        let request = WithdrawRequest::try_from(req).unwrap();
        let node = self.node.clone();
        let f = async move {
            let rx = node
                .withdraw_oneshot(request.remote_addr, request.local_amount)
                .await;
            process_response(rx, sink).await;
        };
        ctx.spawn(f.boxed().unit_error().compat());
    }

    fn channel_balance(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: node_proto::proto::node::ChannelBalanceRequest,
        sink: ::grpcio::UnarySink<node_proto::proto::node::ChannelBalanceResponse>,
    ) {
        let request = ChannelBalanceRequest::try_from(req).unwrap();
        let node = self.node.clone();
        let f = async move {
            let balance = node
                .channel_balance_async(request.remote_addr)
                .await
                .unwrap_or(0);
            let resp = ChannelBalanceResponse::new(balance).into();
            sink.success(resp);
        };
        ctx.spawn(f.boxed().unit_error().compat());
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
        let node = self.node.clone();
        let f = async move {
            match node
                .execute_script_oneshot(
                    request.remote_addr,
                    request.package_name,
                    request.script_name,
                    request.args,
                )
                .await
            {
                Ok(rx) => {
                    process_response(rx, sink).await;
                }
                Err(e) => {
                    set_failure_message(
                        RpcStatusCode::UNKNOWN,
                        format!("Failed to process request: {}", e),
                        sink,
                    );
                }
            }
        };
        ctx.spawn(f.boxed().unit_error().compat());
    }

    fn query_transaction(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: node_proto::proto::node::QueryTransactionQuest,
        sink: ::grpcio::UnarySink<sgtypes::proto::sgtypes::SignedChannelTransaction>,
    ) {
        let node = self.node.clone();
        let f = async move {
            let request = QueryTransactionQuest::try_from(req).unwrap();

            let rx = node
                .get_txn_by_channel_sequence_number(
                    request.participant_address,
                    request.channel_seq_number,
                )
                .await;
            match rx {
                Ok(rx) => {
                    sink.success(rx.into());
                }
                Err(e) => {
                    set_failure_message(
                        RpcStatusCode::UNKNOWN,
                        format!("Failed to process request: {}", e),
                        sink,
                    );
                }
            }
        };
        ctx.spawn(f.boxed().unit_error().compat());
    }

    fn get_channel_transaction_proposal(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: node_proto::proto::node::ChannelBalanceRequest,
        sink: ::grpcio::UnarySink<node_proto::proto::node::GetChannelTransactionProposalResponse>,
    ) {
        let request = ChannelBalanceRequest::try_from(req).unwrap();
        let node = self.node.clone();
        let f = async move {
            let rx = node
                .get_channel_transaction_proposal_oneshot(request.remote_addr)
                .await;
            process_response(rx, sink).await;
        };
        ctx.spawn(f.boxed().unit_error().compat());
    }

    fn channel_transaction_proposal(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: node_proto::proto::node::ChannelTransactionProposalRequest,
        sink: ::grpcio::UnarySink<node_proto::proto::node::EmptyResponse>,
    ) {
        let node = self.node.clone();
        let f = async move {
            let request = ChannelTransactionProposalRequest::try_from(req).unwrap();

            let result = node
                .channel_transaction_proposal_async(
                    request.participant_address,
                    request.transaction_hash,
                    request.approve,
                )
                .await;
            match result {
                Ok(rx) => {
                    sink.success(rx.into());
                }
                Err(e) => {
                    set_failure_message(
                        RpcStatusCode::UNKNOWN,
                        format!("Failed to process request: {}", e),
                        sink,
                    );
                }
            }
        };
        ctx.spawn(f.boxed().unit_error().compat());
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
