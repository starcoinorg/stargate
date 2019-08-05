mod test_helper;

use crate::test_helper::{create_and_start_server,create_keypair};
use node_client::NodeClient;
use futures01::future::Future;
use grpcio::EnvBuilder;
use std::sync::Arc;
use node_service::config::{NodeConfig,get_test_config};
use node_proto::{OpenChannelRequest,OpenChannelResponse};
use types::account_address::AccountAddress;

#[test]
fn test_node_service_basic() {
    let config = get_test_config("localhost".to_string(),8080);
    let (mut node_server) = create_and_start_server(&config);

    let node_client = NodeClient::new(
        Arc::new(EnvBuilder::new().build()),
        &config.network.address,
        config.network.port,
    );

    let remote_addr = AccountAddress::random();
    let open_channel_req = OpenChannelRequest::new(remote_addr);
    let response=node_client.open_channel(open_channel_req);
    node_server.shutdown().wait().unwrap();
}