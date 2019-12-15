use anyhow::{Result, format_err};
use futures::{compat::Future01CompatExt, prelude::*};
use futures_01::future::Future as Future01;
use grpcio::{ChannelBuilder, Environment, EnvBuilder};
use libra_types::{
    account_address::AccountAddress,
    account_state_blob::AccountStateBlob,
    crypto_proxies::{LedgerInfoWithSignatures, ValidatorChangeEventWithProof},
    get_with_proof::{
        RequestItem, ResponseItem, UpdateToLatestLedgerRequest, UpdateToLatestLedgerResponse,
    },
    proof::AccumulatorConsistencyProof,
    proof::SparseMerkleProof,
    transaction::{TransactionListWithProof, TransactionToCommit, Version},
};
use std::convert::TryFrom;
use std::{pin::Pin, sync::Arc};
use faucet_proto::{
    proto::faucet::{FaucetRequest, EmptyResponse, SgFaucetClient},
};
#[cfg(test)]
use faucet_service::{FaucetConf, load_faucet_conf, FaucetNode};
#[cfg(test)]
use libra_logger::prelude::*;

fn make_clients(
    env: Arc<Environment>,
    host: &str,
    port: u16,
    client_type: &str,
    max_receive_len: Option<i32>,
) -> Vec<SgFaucetClient> {
    let num_clients = env.completion_queues().len();
    (0..num_clients)
        .map(|i| {
            let mut builder = ChannelBuilder::new(env.clone())
                .primary_user_agent(format!("grpc/faucet-{}-{}", client_type, i).as_str());
            if let Some(m) = max_receive_len {
                builder = builder.max_receive_message_len(m);
            }
            let channel = builder.connect(&format!("{}:{}", host, port));
            SgFaucetClient::new(channel)
        })
        .collect::<Vec<SgFaucetClient>>()
}

fn convert_grpc_response<T>(
    response: grpcio::Result<impl Future01<Item = T, Error = grpcio::Error>>,
) -> impl Future<Output = Result<T>> {
    future::ready(response.map_err(convert_grpc_err))
        .map_ok(Future01CompatExt::compat)
        .and_then(|x| x.map_err(convert_grpc_err))
}

fn convert_grpc_err(e: grpcio::Error) -> anyhow::Error {
    format_err!("grpc error: {}", e)
}

#[test]
fn test_faucet() {
    ::libra_logger::init_for_e2e_testing();
    //1. chain
    let faucet_path = "/tmp/faucet";
    let (mut node_config, _logger, _handler) = sgchain::main_node::run_node(None, false, false);
    //1.1 save chain node config
    node_config.consensus.save_key(faucet_path);

    //2. faucet server
    //2.1 create FaucetConf
    let mut faucet_conf = load_faucet_conf();
    faucet_conf.set_key_file(faucet_path.to_string());
    let (host, port) = faucet_conf.server();
    //2.2 start server
    let faucet_service = FaucetNode::run(faucet_conf);

    //3. faucet client
    let client_env = Arc::new(EnvBuilder::new().name_prefix("grpc-coord-").build());
    let faucet_client = make_clients(client_env, host.as_str(), port, "read", None);

    loop {
        std::thread::park();
    }
}