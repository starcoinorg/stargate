use failure::prelude::*;
use crate::ChainClient;
use types::{account_config::association_address, account_address::AccountAddress};
use types::transaction::{Version, SignedTransaction, RawTransaction, SignedTransactionWithProof};
use types::proof::SparseMerkleProof;
use star_types::proto::chain::WatchData;
use admission_control_proto::proto::{admission_control_grpc::AdmissionControlClient,
                                     admission_control_client::AdmissionControlClientTrait};
use admission_control_service::admission_control_client::AdmissionControlClient as MockAdmissionControlClient;
use crate::watch_stream::{WatchResp, WatchStream};
use vm_genesis::{encode_transfer_script, encode_create_account_script, GENESIS_KEYPAIR};
use std::time::Duration;
use std::sync::Arc;
use grpcio::{EnvBuilder, ChannelBuilder};
use types::get_with_proof::RequestItem;
use types::proto::get_with_proof::{ResponseItem, UpdateToLatestLedgerRequest, UpdateToLatestLedgerResponse};
use proto_conv::{IntoProto, FromProto};
use types::{account_state_blob::AccountStateBlob, account_config::get_account_resource_or_default};
use core::borrow::Borrow;
use std::convert::TryInto;
use types::account_config::AccountResource;
use admission_control_proto::proto::admission_control::SubmitTransactionRequest;
use executable_helpers::helpers::{
    setup_executable, ARG_CONFIG_PATH, ARG_DISABLE_LOGGING, ARG_PEER_ID,
};
use config::trusted_peers::ConfigHelpers;
use mempool::core_mempool_client::CoreMemPoolClient;
use vm_validator::vm_validator::VMValidator;

#[derive(Clone)]
pub struct StarClient {
    ac_client: AdmissionControlClient,
}

impl StarClient {
    pub fn new(host: &str, port: u32) -> Self {
        let conn_addr = format!("{}:{}", host, port);
        let env = Arc::new(EnvBuilder::new().name_prefix("ac-grpc-client-").build());
        let ch = ChannelBuilder::new(env).connect(&conn_addr);
        Self {
            ac_client: AdmissionControlClient::new(ch),
        }
    }

    fn do_request(&self, req: &UpdateToLatestLedgerRequest) -> UpdateToLatestLedgerResponse {
        self.ac_client.update_to_latest_ledger(req).expect("Call update_to_latest_ledger err.")
    }

    fn get_account_state_with_proof_inner(&self, account_address: &AccountAddress, version: Option<Version>)
                                          -> Result<(Version, Option<Vec<u8>>, SparseMerkleProof)> {
        let req = RequestItem::GetAccountState { address: account_address.clone() };
        let resp = parse_response(self.do_request(&build_request(req, version)));
        let proof = resp.get_get_account_state_response().get_account_state_with_proof();
        let blob = if proof.has_blob() {
            Some(proof.get_blob().get_blob().to_vec())
        } else {
            None
        };
        Ok((proof.version, blob, SparseMerkleProof::from_proto(
            proof.get_proof().get_transaction_info_to_account_proof().clone())
            .expect("SparseMerkleProof parse from proto err.")))
    }

    fn account_exist(&self, account_address: &AccountAddress, version: Option<Version>) -> bool {
        match self.get_account_state_with_proof_inner(account_address, version).expect("get account state err.").1 {
            Some(blob) => true,
            None => false
        }
    }

    fn account_sequence_number(&self, account_address: &AccountAddress) -> Option<Version> {
        match self.get_account_state_with_proof_inner(account_address, None).expect("get account state err.").1 {
            Some(blob) => {
                let a_s_b = AccountStateBlob::from(blob);
                let account_btree = a_s_b.borrow().try_into().expect("blob to btree err.");
                let account_resource = AccountResource::make_from(&account_btree).expect("make account resource err.");
                Some(account_resource.sequence_number())
            }
            None => None
        }
    }
}

impl ChainClient for StarClient {
    type WatchResp = grpcio::ClientSStreamReceiver<WatchData>;

    fn get_account_state_with_proof(&self, account_address: &AccountAddress, version: Option<Version>)
                                    -> Result<(Version, Option<Vec<u8>>, SparseMerkleProof)> {
        self.get_account_state_with_proof_inner(account_address, version)
    }

    fn faucet(&self, receiver: AccountAddress, amount: u64) -> Result<()> {
        let exist_flag = self.account_exist(&receiver, None);
        let script = if !exist_flag {
            encode_create_account_script(&receiver, amount)
        } else {
            encode_transfer_script(&receiver, amount)
        };

        let sender = association_address();
        let s_n = self.account_sequence_number(&sender).expect("seq num is none.");
        let signed_tx = RawTransaction::new_script(
            sender,
            s_n,
            script,
            1000_000 as u64,
            1 as u64,
            Duration::from_secs(u64::max_value()),
        ).sign(&GENESIS_KEYPAIR.0, GENESIS_KEYPAIR.1.clone())
            .unwrap()
            .into_inner();

        self.submit_transaction(signed_tx)
    }

    fn submit_transaction(&self, signed_transaction: SignedTransaction) -> Result<()> {
        let mut req = SubmitTransactionRequest::new();
        req.set_signed_txn(signed_transaction.into_proto());
        self.ac_client.submit_transaction(&req).expect("submit txn err.");
        Ok(())
    }

    fn watch_transaction(&self, address: &AccountAddress, ver: Version) -> Result<WatchStream<Self::WatchResp>> {
        unimplemented!()
    }

    fn get_transaction_by_seq_num(&self, account_address: &AccountAddress, seq_num: u64) -> Result<Option<SignedTransactionWithProof>> {
        let req = RequestItem::GetAccountTransactionBySequenceNumber { account: account_address.clone(), sequence_number: seq_num, fetch_events: false };
        let mut resp = parse_response(self.do_request(&build_request(req, None)));
        let proof = resp.take_get_account_transaction_by_sequence_number_response().take_signed_transaction_with_proof();
        Ok(Some(SignedTransactionWithProof::from_proto(proof).expect("SignedTransaction parse from proto err.")))
    }
}

pub fn build_request(req: RequestItem, ver: Option<Version>) -> UpdateToLatestLedgerRequest {
    let mut repeated = ::protobuf::RepeatedField::new();
    repeated.push(req.into_proto());
    let mut req = UpdateToLatestLedgerRequest::new();
    req.set_requested_items(repeated);
    match ver {
        Some(v) => req.set_client_known_version(v),
        None => {}
    }

    req
}

pub fn parse_response(resp: UpdateToLatestLedgerResponse) -> ResponseItem {
    resp.get_response_items().get(0).expect("response item is none.").clone()
}

//pub fn create_star_client(host: &str, port: u32) -> StarClient {
//    let conn_addr = format!("{}:{}", host, port);
//    let env = Arc::new(EnvBuilder::new().name_prefix("ac-grpc-client-").build());
//    let ch = ChannelBuilder::new(env).connect(&conn_addr);
//    StarClient::new(AdmissionControlClient::new(ch))
//}
//
//pub fn mock_star_client() -> (StarClient, StarHandle) {
//    let (mut config, _logger, _args) = setup_executable(
//        "Mock star single node".to_string(),
//        vec![ARG_PEER_ID, ARG_CONFIG_PATH, ARG_DISABLE_LOGGING],
//    );
//    if config.consensus.get_consensus_peers().len() == 0 {
//        let (_, single_peer_consensus_config) = ConfigHelpers::get_test_consensus_config(1, None);
//        config.consensus.consensus_peers = single_peer_consensus_config;
//        let genesis_path = star_node::genesis::genesis_blob();
//        config.execution.genesis_file_location = genesis_path;
//    }
//
//    let (ac_client, node_handle) = setup_environment(&mut config);
//    (StarClient::new(ac_client), node_handle)
//}