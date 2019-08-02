use node_proto::proto::node_grpc::create_node;
use node_service::NodeService;
use grpc_helpers::ServerHandle;
use grpcio::{EnvBuilder, ServerBuilder};
use config::{NodeConfig};
use std::{sync::Arc};

pub fn create_and_start_server(&config:NodeConfig) -> (grpcio::Server) {
    let client_env = Arc::new(EnvBuilder::new().build());
    let node_service = create_node(NodeService::new());
    let mut node_server = ServerBuilder::new(Arc::new(EnvBuilder::new().build()))
        .register_service(node_service)
        .bind(config.network.address.clone(), config.network.port)
        .build()
        .expect("Failed to create execution server.");
    node_server.start();

    (node_server)
}
