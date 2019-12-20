use crate::faucet_config;
use base64::decode;
use faucet_config::{load_faucet_conf, FaucetConf};
use faucet_proto::proto::faucet::{
    create_sg_faucet, FaucetRequest as FaucetRequestProto, SgFaucet,
};
use faucet_proto::FaucetRequest;
use grpc_helpers::{provide_grpc_response, spawn_service_thread_with_drop_closure, ServerHandle};
use libra_config::config::ConsensusKeyPair;
use libra_crypto::ed25519::*;
use libra_logger::prelude::*;
use sgchain::star_chain_client::{ChainClient, StarChainClient};
use std::path::PathBuf;
use std::{clone::Clone, convert::TryFrom, fs, sync::Arc};
use tokio::runtime::Runtime;

pub struct FaucetNode {}

impl FaucetNode {
    pub fn load_and_run() -> ServerHandle {
        let current_dir = PathBuf::from("./");
        let faucet_conf = load_faucet_conf(format!(
            "{}/{}",
            fs::canonicalize(&current_dir)
                .expect("path err.")
                .to_str()
                .expect("str err."),
            "sgfaucet/faucet-service"
        ));
        Self::run(faucet_conf)
    }

    pub fn run(faucet_conf: FaucetConf) -> ServerHandle {
        let (host, port) = faucet_conf.server();
        let faucet_service = SgFaucetService::new(faucet_conf);
        spawn_service_thread_with_drop_closure(
            create_sg_faucet(faucet_service.clone()),
            host,
            port,
            "faucet",
            Some(100_000_000),
            move || {
                //                shutdown_receiver.recv().expect(
                //                    "Failed to receive on shutdown channel when storage service was dropped",
                //                )
            },
        )
    }
}

#[derive(Clone)]
pub struct SgFaucetService {
    chain_client: StarChainClient,
    key_pair: Arc<Ed25519PrivateKey>,
}

impl SgFaucetService {
    pub fn new(faucet_conf: FaucetConf) -> Self {
        let (host, port) = faucet_conf.chain();
        let chain_client = StarChainClient::new(host.as_str(), port as u32);
        let pri_file = faucet_conf.pri_file().expect("pri key is none.");
        let key_base64 =
            decode(&fs::read(pri_file).expect("read pri file err.")).expect("base64 decode err.");
        let pri_key =
            Ed25519PrivateKey::try_from(key_base64.as_ref()).expect("Ed25519PrivateKey parse err.");
        //        let key_pair = generate_keypair::load_key_from_file(
        //            pri_file,
        //        ).expect("Faucet account key is required to generate config");

        let key_pair = ConsensusKeyPair::load(pri_key)
            .take_private()
            .expect("pri key is none.");

        SgFaucetService {
            chain_client,
            key_pair: Arc::new(key_pair),
        }
    }
}

impl SgFaucet for SgFaucetService {
    fn faucet(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: FaucetRequestProto,
        sink: ::grpcio::UnarySink<()>,
    ) {
        let faucet_req = FaucetRequest::try_from(req).expect("parse err.");
        let mut rt = Runtime::new().expect("faucet runtime err.");
        let chain_client = self.chain_client.clone();
        let mut can_faucet = false;
        let exist_flag = chain_client.account_exist(&faucet_req.address, None);
        if !exist_flag {
            can_faucet = true;
        } else {
            let account_state = chain_client.get_account_state(faucet_req.address, None);
            match account_state {
                Ok(account) => match account.get_account_resource() {
                    Some(a_r) => {
                        if a_r.balance() < 10_000_000 {
                            can_faucet = true;
                        }
                    }
                    None => {
                        can_faucet = true;
                    }
                },
                Err(e) => {
                    warn!("{:?}", e);
                }
            }
        }

        if can_faucet {
            let f = async move {
                chain_client
                    .faucet_with_sender(
                        None,
                        self.key_pair.as_ref(),
                        faucet_req.address,
                        faucet_req.amount,
                    )
                    .await
            };
            rt.block_on(f).expect("faucet err.");
        }

        provide_grpc_response(Ok(()), ctx, sink);
    }
}
