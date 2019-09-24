use admission_control_proto::proto::admission_control_client::AdmissionControlClientTrait;
use std::sync::Arc;
use config::trusted_peers::ConfigHelpers;
use crate::mock_star_node::{setup_environment, StarHandle};
use executable_helpers::helpers::{
    setup_executable, ARG_CONFIG_PATH, ARG_DISABLE_LOGGING, ARG_PEER_ID,
};
use chain_client::{ChainClient, watch_stream::WatchStream};
use futures::{
    sync::mpsc::UnboundedReceiver,
    Stream, Poll,
};
use star_types::proto::chain::WatchData;
use types::{proof::SparseMerkleProof, transaction::{SignedTransactionWithProof, RawTransaction, SignedTransaction, Version},
            account_config::association_address, account_address::AccountAddress, get_with_proof::RequestItem};
use failure::prelude::*;
use admission_control_service::admission_control_client::AdmissionControlClient;
use mempool::core_mempool_client::CoreMemPoolClient;
use vm_validator::vm_validator::VMValidator;
use chain_client::star_client::{build_request, parse_response};
use types::proto::get_with_proof::{ResponseItem, UpdateToLatestLedgerRequest, UpdateToLatestLedgerResponse};
use proto_conv::{IntoProto, FromProto};
use types::{account_state_blob::AccountStateBlob, account_config::get_account_resource_or_default};
use core::borrow::Borrow;
use std::convert::TryInto;
use types::account_config::AccountResource;
use std::time::Duration;
use admission_control_proto::proto::admission_control::SubmitTransactionRequest;
use vm_genesis::{encode_transfer_script, encode_create_account_script, GENESIS_KEYPAIR};

pub struct MockStreamReceiver<T> {
    inner_rx: UnboundedReceiver<T>
}

impl<T> Stream for MockStreamReceiver<T> {
    type Item = T;
    type Error = grpcio::Error;

    fn poll(&mut self) -> Poll<Option<T>, Self::Error> {
        self.inner_rx.poll().map_err(|e| { grpcio::Error::RemoteStopped })
    }
}

#[derive(Clone)]
pub struct MockStarClient {
    ac_client: Arc<AdmissionControlClient<CoreMemPoolClient, VMValidator>>,
}

impl MockStarClient {
    pub fn new() -> (Self, StarHandle) {
        let (mut config, _logger, _args) = setup_executable(
            "Mock star single node".to_string(),
            vec![ARG_PEER_ID, ARG_CONFIG_PATH, ARG_DISABLE_LOGGING],
        );
        if config.consensus.get_consensus_peers().len() == 0 {
            let (_, single_peer_consensus_config) = ConfigHelpers::get_test_consensus_config(1, None);
            config.consensus.consensus_peers = single_peer_consensus_config;
            let genesis_path = star_node::genesis::genesis_blob();
            config.execution.genesis_file_location = genesis_path;
        }

        let (ac_client, node_handle) = setup_environment(&mut config);
        (MockStarClient { ac_client:Arc::new(ac_client) }, node_handle)
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

impl ChainClient for MockStarClient {
    type WatchResp = MockStreamReceiver<WatchData>;

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