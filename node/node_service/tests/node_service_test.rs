mod test_helper;

use crate::test_helper::create_and_start_server;
use futures01::future::Future as Future01;
use grpcio::EnvBuilder;
use node_client::NodeClient;
use node_proto::{OpenChannelRequest};
use sg_config::config::get_test_config;
use std::sync::Arc;
use tokio::runtime::Runtime;
use libra_types::account_address::AccountAddress;

#[test]
fn test_node_service_basic() {
    let config = get_test_config("localhost".to_string(), 8080, 8081);
    let rt = Runtime::new().unwrap();
    let executor = rt.executor();

    let mut node_server = create_and_start_server(&config, executor);

    let node_client = NodeClient::new(
        Arc::new(EnvBuilder::new().build()),
        &config.rpc_config.address,
        config.rpc_config.port,
    );

    let remote_addr = AccountAddress::random();
    let open_channel_req = OpenChannelRequest::new(remote_addr, 1, 1);
    let _response = node_client.open_channel(open_channel_req);
    node_server.shutdown().wait().unwrap();

    rt.shutdown_on_idle()
}
