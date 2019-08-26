use crypto::{
    ed25519::*,
    traits::{Signature, SigningKey, Uniform},
};
use grpc_helpers::ServerHandle;
use grpcio::{EnvBuilder, ServerBuilder};
use node_proto::proto::node_grpc::create_node;
use node_service::NodeService;
use rand::{rngs::StdRng, SeedableRng};

use tokio::runtime::{Runtime,TaskExecutor};
use node_internal::test_helper::{*};

use sg_config::config::NodeConfig;
use std::sync::Arc;

pub fn create_and_start_server(config: &NodeConfig,executor:TaskExecutor) -> (grpcio::Server) {
    let client_env = Arc::new(EnvBuilder::new().build());

    let (node,addr,keypair) = gen_node(executor,&config.net_config);
    let node_service = create_node(NodeService::new(Arc::new(node)));
    let mut node_server = ServerBuilder::new(Arc::new(EnvBuilder::new().build()))
        .register_service(node_service)
        .bind(config.rpc_config.address.clone(), config.rpc_config.port)
        .build()
        .expect("Failed to create execution server.");
    node_server.start();

    (node_server)
}


pub fn create_keypair()->(Ed25519PublicKey,Ed25519PrivateKey){
    let mut rng: StdRng = SeedableRng::from_seed([0; 32]);
    let private_key = Ed25519PrivateKey::generate_for_testing(&mut rng);
    let public_key: Ed25519PublicKey = (&private_key).into();
    (public_key,private_key)
}
