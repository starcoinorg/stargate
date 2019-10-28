// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::mock_star_node::{setup_environment, StarHandle};
use admission_control_proto::proto::admission_control::{
    AdmissionControlClient, SubmitTransactionRequest, SubmitTransactionResponse,
};
use admission_control_service::admission_control_mock_client::AdmissionControlMockClient;
use async_trait::async_trait;
use config::config::NodeConfig;
use config::config::NodeConfigHelpers;
use core::borrow::Borrow;
use failure::prelude::*;
use futures::channel::oneshot::Sender;
use grpcio::{ChannelBuilder, EnvBuilder};
use libra_types::get_with_proof::ResponseItem;
use libra_types::{
    account_address::AccountAddress,
    account_config::{association_address, AccountResource},
    account_state_blob::{AccountStateBlob, AccountStateWithProof},
    get_with_proof::RequestItem,
    proof::SparseMerkleProof,
    proto::types::{UpdateToLatestLedgerRequest, UpdateToLatestLedgerResponse},
    transaction::{RawTransaction, SignedTransaction, SignedTransactionWithProof, Version},
};
use logger::prelude::*;
use prost_ext::MessageExt;
use sgtypes::account_state::AccountState;
use std::{
    convert::TryInto,
    fs::File,
    io::Write,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::runtime::Runtime;
use tokio::timer::delay;
use transaction_builder::{encode_create_account_script, encode_transfer_script};
use vm_genesis::{encode_genesis_transaction, GENESIS_KEYPAIR};

#[async_trait]
pub trait ChainClient: Send + Sync {
    fn submit_transaction(
        &self,
        req: &SubmitTransactionRequest,
    ) -> ::grpcio::Result<SubmitTransactionResponse>;

    fn update_to_latest_ledger(
        &self,
        req: &UpdateToLatestLedgerRequest,
    ) -> ::grpcio::Result<UpdateToLatestLedgerResponse>;

    fn get_account_state(
        &self,
        account: AccountAddress,
        version: Option<Version>,
    ) -> Result<AccountState> {
        let (version, state_blob, proof) = self
            .get_account_state_with_proof(&account, version)
            .and_then(|(version, state, proof)| {
                Ok((
                    version,
                    state.ok_or(format_err!("can not find account by address:{}", account))?,
                    proof,
                ))
            })?;
        AccountState::from_account_state_blob(version, state_blob, proof)
    }

    fn get_account_state_with_proof(
        &self,
        account_address: &AccountAddress,
        version: Option<Version>,
    ) -> Result<(Version, Option<Vec<u8>>, SparseMerkleProof)> {
        self.get_account_state_with_proof_inner(account_address, version)
    }

    async fn faucet(&self, receiver: AccountAddress, amount: u64) -> Result<()> {
        let exist_flag = self.account_exist(&receiver, None);
        let script = if !exist_flag {
            encode_create_account_script(&receiver, amount)
        } else {
            encode_transfer_script(&receiver, amount)
        };

        let sender = association_address();
        let s_n = self
            .account_sequence_number(&sender)
            .expect("seq num is none.");
        let signed_tx = RawTransaction::new_script(
            sender.clone(),
            s_n,
            script,
            1000_000 as u64,
            1 as u64,
            Duration::from_secs(u64::max_value()),
        )
        .sign(&GENESIS_KEYPAIR.0, GENESIS_KEYPAIR.1.clone())
        .unwrap()
        .into_inner();

        self.submit_signed_transaction(signed_tx)
            .expect("commit signed txn err.");
        self.watch_transaction(&sender, s_n).await.unwrap();
        Ok(())
    }

    fn submit_signed_transaction(&self, signed_transaction: SignedTransaction) -> Result<()> {
        let mut req = SubmitTransactionRequest::default();
        req.signed_txn = Some(signed_transaction.into());
        self.submit_transaction(&req).expect("submit txn err.");
        Ok(())
    }

    async fn watch_transaction(
        &self,
        address: &AccountAddress,
        seq: u64,
    ) -> Result<(
        Option<SignedTransactionWithProof>,
        Option<AccountStateWithProof>,
    )> {
        let end_time = Instant::now() + Duration::from_millis(10_000);
        loop {
            let timeout_time = Instant::now() + Duration::from_millis(1000);
            delay(timeout_time).await;
            debug!("watch address : {:?}, seq number : {}", address, seq);
            let (tx_proof, account_proof) = self.get_transaction_by_seq_num(address, seq)?;
            let flag = timeout_time >= end_time;
            match tx_proof {
                None => {
                    if flag {
                        return Ok((None, account_proof));
                    }
                    continue;
                }
                Some(t) => {
                    return Ok((Some(t), account_proof));
                }
            }
        }
    }

    fn get_transaction_by_seq_num(
        &self,
        account_address: &AccountAddress,
        seq_num: u64,
    ) -> Result<(
        Option<SignedTransactionWithProof>,
        Option<AccountStateWithProof>,
    )> {
        let req = RequestItem::GetAccountTransactionBySequenceNumber {
            account: account_address.clone(),
            sequence_number: seq_num,
            fetch_events: false,
        };
        let resp = parse_response(self.do_request(&build_request(req, None)));
        resp.into_get_account_txn_by_seq_num_response()
    }

    fn do_request(&self, req: &UpdateToLatestLedgerRequest) -> UpdateToLatestLedgerResponse {
        self.update_to_latest_ledger(req)
            .expect("Call update_to_latest_ledger err.")
    }

    fn get_account_state_with_proof_inner(
        &self,
        account_address: &AccountAddress,
        version: Option<Version>,
    ) -> Result<(Version, Option<Vec<u8>>, SparseMerkleProof)> {
        let req = RequestItem::GetAccountState {
            address: account_address.clone(),
        };
        let resp = parse_response(self.do_request(&build_request(req, version)))
            .into_get_account_state_response()?;
        let proof = resp.proof;
        let blob = resp.blob.map(|blob| blob.into());
        //TODO should return whole proof.
        Ok((
            resp.version,
            blob,
            proof.transaction_info_to_account_proof().clone(),
        ))
    }

    fn account_exist(&self, account_address: &AccountAddress, version: Option<Version>) -> bool {
        match self
            .get_account_state_with_proof_inner(account_address, version)
            .expect("get account state err.")
            .1
        {
            Some(_blob) => true,
            None => false,
        }
    }

    fn account_sequence_number(&self, account_address: &AccountAddress) -> Option<Version> {
        match self
            .get_account_state_with_proof_inner(account_address, None)
            .expect("get account state err.")
            .1
        {
            Some(blob) => {
                let a_s_b = AccountStateBlob::from(blob);
                let account_btree = a_s_b.borrow().try_into().expect("blob to btree err.");
                let account_resource =
                    AccountResource::make_from(&account_btree).expect("make account resource err.");
                Some(account_resource.sequence_number())
            }
            None => None,
        }
    }
}

#[derive(Clone)]
pub struct StarChainClient {
    ac_client: Arc<AdmissionControlClient>,
}

impl StarChainClient {
    pub fn new(host: &str, port: u32) -> Self {
        let conn_addr = format!("{}:{}", host, port);
        let env = Arc::new(EnvBuilder::new().name_prefix("ac-grpc-client-").build());
        let ch = ChannelBuilder::new(env).connect(&conn_addr);
        let ac_client = AdmissionControlClient::new(ch);
        StarChainClient {
            ac_client: Arc::new(ac_client),
        }
    }
}

impl ChainClient for StarChainClient {
    fn submit_transaction(
        &self,
        req: &SubmitTransactionRequest,
    ) -> ::grpcio::Result<SubmitTransactionResponse> {
        self.ac_client.submit_transaction(req)
    }

    fn update_to_latest_ledger(
        &self,
        req: &UpdateToLatestLedgerRequest,
    ) -> ::grpcio::Result<UpdateToLatestLedgerResponse> {
        self.ac_client.update_to_latest_ledger(req)
    }
}

#[derive(Clone)]
pub struct MockChainClient {
    ac_client: Arc<AdmissionControlMockClient>,
    // just wait client to be drop.
    _shutdown_sender: Arc<Sender<()>>,
}

impl MockChainClient {
    pub fn new() -> (Self, StarHandle) {
        let mut config =
            NodeConfigHelpers::get_single_node_test_config(false /* random ports */);
        // TODO: test the circleci
        config.storage.address = "127.0.0.1".to_string();
        info!("MockChainClient config: {:?} ", config);
        //        if config.consensus.consensus_peers.peers.len() == 0 {
        //            let (_, single_peer_consensus_config,_) =
        //                ConfigHelpers::gen_validator_nodes(1, None);
        //            config.consensus.consensus_peers = single_peer_consensus_config;
        //            genesis_blob(&config.execution.genesis_file_location);
        //        }
        genesis_blob(&config);

        let (_handle, shutdown_sender, ac) = setup_environment(&mut config);
        (
            MockChainClient {
                ac_client: Arc::new(AdmissionControlMockClient::new(ac)),
                _shutdown_sender: Arc::new(shutdown_sender),
            },
            _handle,
        )
    }
}

impl ChainClient for MockChainClient {
    fn submit_transaction(
        &self,
        req: &SubmitTransactionRequest,
    ) -> ::grpcio::Result<SubmitTransactionResponse> {
        self.ac_client.submit_transaction(req)
    }

    fn update_to_latest_ledger(
        &self,
        req: &UpdateToLatestLedgerRequest,
    ) -> ::grpcio::Result<UpdateToLatestLedgerResponse> {
        self.ac_client.update_to_latest_ledger(req)
    }
}

fn build_request(req: RequestItem, ver: Option<Version>) -> UpdateToLatestLedgerRequest {
    libra_types::get_with_proof::UpdateToLatestLedgerRequest::new(ver.unwrap_or(0), vec![req])
        .into()
}

pub fn faucet_sync<C>(client: C, receiver: AccountAddress, amount: u64) -> Result<()>
where
    C: 'static + ChainClient,
{
    let rt = Runtime::new().expect("faucet runtime err.");
    let f = async move { client.faucet(receiver, amount).await };
    rt.block_on(f)
}

fn parse_response(mut resp: UpdateToLatestLedgerResponse) -> ResponseItem {
    //TODO fix unwrap
    //.expect("response item is none.")
    resp.response_items.remove(0).try_into().unwrap()
}

pub fn genesis_blob(config: &NodeConfig) {
    let path = config.get_genesis_transaction_file();
    info!("Write genesis_blob to {}", path.as_path().to_string_lossy());
    let genesis_checked_txn =
        encode_genesis_transaction(&GENESIS_KEYPAIR.0, GENESIS_KEYPAIR.1.clone());
    let genesis_txn = genesis_checked_txn.into_inner();
    let mut genesis_file = File::create(path).expect("open genesis file err.");
    genesis_file
        .write_all(
            Into::<libra_types::proto::types::SignedTransaction>::into(genesis_txn)
                .to_vec()
                .unwrap()
                .as_slice(),
        )
        .expect("write genesis file err.");
    genesis_file.flush().expect("flush genesis file err.");
}
