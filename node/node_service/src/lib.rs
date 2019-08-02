#![feature(async_await)]

//use config::config::NodeConfig;
use node_proto::{OpenChannelRequest,OpenChannelResponse,PayRequest,PayResponse};
use failure::Result;
use futures01::future::Future;
use futures03::{
    channel::oneshot,
    future::{FutureExt, TryFutureExt},
};
use grpc_helpers::default_reply_error_logger;
use grpcio::{RpcStatus, RpcStatusCode};
use proto_conv::{FromProto, IntoProto};
use std::sync::Arc;

#[derive(Clone)]
pub struct NodeService {
}

impl NodeService {
    pub fn new() -> Self {
        NodeService {  }
    }
}

impl node_proto::proto::node_grpc::Node for NodeService {
    fn open_channel(&mut self, ctx: ::grpcio::RpcContext, req: node_proto::proto::node::OpenChannelRequest, sink: ::grpcio::UnarySink<node_proto::proto::node::OpenChannelResponse>){

    }
    fn pay(&mut self, ctx: ::grpcio::RpcContext, req: node_proto::proto::node::PayRequest, sink: ::grpcio::UnarySink<node_proto::proto::node::PayResponse>){

    }

    fn send_off_line_tx(&mut self, ctx: ::grpcio::RpcContext, req: node_proto::proto::node::SendOffLineTxRequest, sink: ::grpcio::UnarySink<node_proto::proto::node::SendOffLineTxResponse>){

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
