#![feature(async_await)]

//use config::config::NodeConfig;
use node_proto::{
    OpenChannelRequest,OpenChannelResponse,PayRequest,PayResponse,ConnectRequest,ConnectResponse,
    proto::node_grpc::create_node
};
use failure::Result;
use futures01::future::Future;
use futures03::{
    channel::oneshot,
    future::{FutureExt, TryFutureExt},
    io::{AsyncRead, AsyncWrite},
};
use grpc_helpers::{provide_grpc_response, spawn_service_thread_with_drop_closure, ServerHandle,default_reply_error_logger};
use grpcio::{RpcStatus, RpcStatusCode,EnvBuilder};
use proto_conv::{FromProto, IntoProto};
use std::sync::{Arc,Mutex,mpsc};
use sg_config::config::{NodeConfig};
use node_internal::node::Node as Node_Internal;
use netcore::transport::{Transport};
use chain_client::{ChainClient};
use types::account_config::coin_struct_tag;

pub fn setup_node_service<C,TTransport>(config: &NodeConfig,node:Arc<Node_Internal<C,TTransport>>) -> ::grpcio::Server 
where C: ChainClient+Clone+ Send+Sync+'static,
TTransport:Transport+Sync+Send+Clone+'static,
TTransport::Output: AsyncWrite+AsyncRead+Unpin+Send{
    let client_env = Arc::new(EnvBuilder::new().name_prefix("grpc-node-").build());

    let handle = NodeService::new(node);
    let service = create_node(handle);
    ::grpcio::ServerBuilder::new(Arc::new(EnvBuilder::new().name_prefix("grpc-node-").build()))
        .register_service(service)
        .bind(config.network.address.clone(), config.network.port)
        .build()
        .expect("Unable to create grpc server")
}

#[derive(Clone)]
pub struct NodeService  <C: ChainClient+Clone+Send+Sync+'static,TTransport:Transport+Sync+Send+Clone+'static>
    where TTransport::Output: AsyncWrite+AsyncRead+Unpin+Send{
        node:Arc<Node_Internal<C,TTransport>>
}

impl<C: ChainClient+Clone +Send+Sync+'static,TTransport:Transport+Sync+Send+Clone+'static> NodeService<C,TTransport> 
where TTransport::Output: AsyncWrite+AsyncRead+Unpin+Send{
    pub fn new(node:Arc<Node_Internal<C,TTransport>>) -> Self {
        NodeService { 
            node,
        }
    }
}

impl<C: ChainClient+Clone +Send+Sync+'static,TTransport:Transport+Sync+Send+Clone+'static> node_proto::proto::node_grpc::Node for NodeService<C,TTransport> 
where TTransport::Output: AsyncWrite+AsyncRead+Unpin+Send{
    fn open_channel(&mut self, ctx: ::grpcio::RpcContext, req: node_proto::proto::node::OpenChannelRequest, sink: ::grpcio::UnarySink<node_proto::proto::node::OpenChannelResponse>){
        println!("open channel");
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
        self.node.connect(connect_req.remote_ip.parse().unwrap(),connect_req.remote_addr);
        let resp=ConnectResponse{}.into_proto();
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
