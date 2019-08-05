#![feature(async_await)]

//use config::config::NodeConfig;
use node_proto::{
    OpenChannelRequest,OpenChannelResponse,PayRequest,PayResponse,
    proto::node_grpc::create_node
};
use failure::Result;
use futures01::future::Future;
use futures03::{
    channel::oneshot,
    future::{FutureExt, TryFutureExt},
};
use grpc_helpers::{provide_grpc_response, spawn_service_thread_with_drop_closure, ServerHandle,default_reply_error_logger};
use grpcio::{RpcStatus, RpcStatusCode,EnvBuilder};
use proto_conv::{FromProto, IntoProto};
use std::sync::{Arc,Mutex,mpsc};
use sg_config::config::{NodeConfig};


pub fn setup_node_service(config: &NodeConfig) -> ::grpcio::Server {
    let client_env = Arc::new(EnvBuilder::new().name_prefix("grpc-node-").build());

    let handle = NodeService::new();
    let service = create_node(handle);
    ::grpcio::ServerBuilder::new(Arc::new(EnvBuilder::new().name_prefix("grpc-node-").build()))
        .register_service(service)
        .bind(config.network.address.clone(), config.network.port)
        .build()
        .expect("Unable to create grpc server")
}

#[derive(Clone)]
pub struct NodeService {
}

impl NodeService {
    pub fn new() -> Self {
        NodeService { 
        }
    }
}

impl node_proto::proto::node_grpc::Node for NodeService {
    fn open_channel(&mut self, ctx: ::grpcio::RpcContext, req: node_proto::proto::node::OpenChannelRequest, sink: ::grpcio::UnarySink<node_proto::proto::node::OpenChannelResponse>){
        println!("open channel");
    }
    fn pay(&mut self, ctx: ::grpcio::RpcContext, req: node_proto::proto::node::PayRequest, sink: ::grpcio::UnarySink<node_proto::proto::node::PayResponse>){
        println!("pay");
    }

    fn send_off_line_tx(&mut self, ctx: ::grpcio::RpcContext, req: node_proto::proto::node::SendOffLineTxRequest, sink: ::grpcio::UnarySink<node_proto::proto::node::SendOffLineTxResponse>){
        println!("send off line tx");
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
