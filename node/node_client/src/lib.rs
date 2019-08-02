use node_proto::{
    proto::{ node_grpc},
};
use failure::{bail, Result};
use grpcio::{ChannelBuilder, Environment};
use proto_conv::{FromProto, IntoProto};
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

}
