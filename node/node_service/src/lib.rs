#![feature(async_await)]

//use config::config::NodeConfig;
use node_proto::{
    OpenChannelRequest,OpenChannelResponse,PayRequest,PayResponse,ConnectRequest,ConnectResponse,DepositRequest,DepositResponse,WithdrawRequest,WithdrawResponse,ChannelBalanceRequest,ChannelBalanceResponse,
    proto::node_grpc::create_node
};
use failure::Result;
use futures01::future::Future;
use futures03::{
    channel::oneshot,
};
use grpc_helpers::{provide_grpc_response, spawn_service_thread_with_drop_closure, ServerHandle,default_reply_error_logger};
use grpcio::{RpcStatus, RpcStatusCode,EnvBuilder};
use proto_conv::{FromProto, IntoProto};
use std::sync::{Arc,Mutex,mpsc};
use sg_config::config::{NodeConfig};
use node_internal::node::Node as Node_Internal;
use chain_client::{ChainClient};
use types::account_config::coin_struct_tag;

pub fn setup_node_service<C>(config: &NodeConfig,node:Arc<Node_Internal<C>>) -> ::grpcio::Server 
where C: ChainClient+Clone+ Send+Sync+'static{
    let client_env = Arc::new(EnvBuilder::new().name_prefix("grpc-node-").build());

    let handle = NodeService::new(node);
    let service = create_node(handle);
    ::grpcio::ServerBuilder::new(Arc::new(EnvBuilder::new().name_prefix("grpc-node-").build()))
        .register_service(service)
        .bind(config.rpc_config.address.clone(), config.rpc_config.port)
        .build()
        .expect("Unable to create grpc server")
}

#[derive(Clone)]
pub struct NodeService  <C: ChainClient+Clone+Send+Sync+'static>{
        node:Arc<Node_Internal<C>>
}

impl<C: ChainClient+Clone +Send+Sync+'static> NodeService<C> {
    pub fn new(node:Arc<Node_Internal<C>>) -> Self {
        NodeService { 
            node,
        }
    }
}

impl<C: ChainClient+Clone +Send+Sync+'static> node_proto::proto::node_grpc::Node for NodeService<C> {
    fn open_channel(&mut self, ctx: ::grpcio::RpcContext, req: node_proto::proto::node::OpenChannelRequest, sink: ::grpcio::UnarySink<node_proto::proto::node::OpenChannelResponse>){
        let request = OpenChannelRequest::from_proto(req).unwrap();
        self.node.open_channel( request.remote_addr, request.local_amount,request.remote_amount).unwrap();
        let resp=OpenChannelResponse{}.into_proto();
        provide_grpc_response(Ok(resp),ctx,sink);
    }

    fn pay(&mut self, ctx: ::grpcio::RpcContext, req: node_proto::proto::node::PayRequest, sink: ::grpcio::UnarySink<node_proto::proto::node::PayResponse>){
        let request = PayRequest::from_proto(req).unwrap();
        self.node.off_chain_pay(coin_struct_tag(), request.remote_addr, request.amount).unwrap();
        let resp=PayResponse{}.into_proto();
        provide_grpc_response(Ok(resp),ctx,sink);
    }

    fn send_off_line_tx(&mut self, ctx: ::grpcio::RpcContext, req: node_proto::proto::node::SendOffLineTxRequest, sink: ::grpcio::UnarySink<node_proto::proto::node::SendOffLineTxResponse>){
        println!("send off line tx");
    }  

    fn connect(&mut self, ctx: ::grpcio::RpcContext, req: node_proto::proto::node::ConnectRequest, sink: ::grpcio::UnarySink<node_proto::proto::node::ConnectResponse>){
        let connect_req = ConnectRequest::from_proto(req).unwrap();
        //self.node.connect(connect_req.remote_ip.parse().unwrap(),connect_req.remote_addr);
        let resp=ConnectResponse{}.into_proto();
        provide_grpc_response(Ok(resp),ctx,sink);
    }

    fn deposit(&mut self, ctx: ::grpcio::RpcContext, req: node_proto::proto::node::DepositRequest, sink: ::grpcio::UnarySink<node_proto::proto::node::DepositResponse>){
        let request = DepositRequest::from_proto(req).unwrap();
        self.node.deposit(coin_struct_tag(), request.remote_addr, request.local_amount,request.remote_amount).unwrap();
        let resp=DepositResponse{}.into_proto();
        provide_grpc_response(Ok(resp),ctx,sink);
    }

    fn withdraw(&mut self, ctx: ::grpcio::RpcContext, req: node_proto::proto::node::WithdrawRequest, sink: ::grpcio::UnarySink<node_proto::proto::node::WithdrawResponse>){
        let request = WithdrawRequest::from_proto(req).unwrap();
        self.node.withdraw(coin_struct_tag(), request.remote_addr, request.local_amount,request.remote_amount).unwrap();
        let resp=WithdrawResponse{}.into_proto();
        provide_grpc_response(Ok(resp),ctx,sink);
    }

    fn channel_balance(&mut self, ctx: ::grpcio::RpcContext, req: node_proto::proto::node::ChannelBalanceRequest, sink: ::grpcio::UnarySink<node_proto::proto::node::ChannelBalanceResponse>){
        let request = ChannelBalanceRequest::from_proto(req).unwrap();
        let balance=self.node.channel_balance(request.remote_addr,coin_struct_tag()).unwrap();
        let resp=ChannelBalanceResponse::new(balance).into_proto();
        provide_grpc_response(Ok(resp),ctx,sink);
    }

}

async fn process_response<T>(
    resp: oneshot::Receiver<Result<T>>,
    sink: grpcio::UnarySink<<T as IntoProto>::ProtoType>,
) where
    T: IntoProto,
{
    match resp.await {
        Ok(Ok(response)) => {
            sink.success(response.into_proto());
        }
        Ok(Err(err)) => {
            set_failure_message(
                RpcStatusCode::Unknown,
                format!("Failed to process request: {}", err),
                sink,
            );
        }
        Err(oneshot::Canceled) => {
            set_failure_message(
                RpcStatusCode::Internal,
                "Executor Internal error: sender is dropped.".to_string(),
                sink,
            );
        }
    }
}

fn process_conversion_error<T>(
    err: failure::Error,
    sink: grpcio::UnarySink<T>,
) -> impl Future<Item = (), Error = ()> {
    set_failure_message(
        RpcStatusCode::InvalidArgument,
        format!("Failed to convert request from Protobuf: {}", err),
        sink,
    )
    .map_err(default_reply_error_logger)
}

fn set_failure_message<T>(
    status_code: RpcStatusCode,
    details: String,
    sink: grpcio::UnarySink<T>,
) -> grpcio::UnarySinkResult {
    let status = RpcStatus::new(status_code, Some(details));
    sink.fail(status)
}
