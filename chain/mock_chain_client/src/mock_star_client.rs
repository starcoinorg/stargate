//use admission_control_proto::proto::admission_control_client::AdmissionControlClientTrait;
//use std::sync::Arc;
//use config::trusted_peers::ConfigHelpers;
//use crate::mock_star_node::{setup_environment, StarHandle};
//use executable_helpers::helpers::{
//    setup_executable, ARG_CONFIG_PATH, ARG_DISABLE_LOGGING, ARG_PEER_ID,
//};
//use chain_client::{ChainClient, watch_stream::WatchStream};
//use futures::{
//    sync::mpsc::UnboundedReceiver,
//    Stream, Poll,
//};
//use star_types::proto::chain::WatchData;
//use types::{proof::SparseMerkleProof, transaction::{SignedTransactionWithProof, SignedTransaction, Version},
//            account_config::association_address, account_address::AccountAddress};
//use failure::prelude::*;
//use admission_control_service::admission_control_client::AdmissionControlClient;
//
//pub struct MockStreamReceiver<T> {
//    inner_rx: UnboundedReceiver<T>
//}
//
//impl<T> Stream for MockStreamReceiver<T> {
//    type Item = T;
//    type Error = grpcio::Error;
//
//    fn poll(&mut self) -> Poll<Option<T>, Self::Error> {
//        self.inner_rx.poll().map_err(|e| { grpcio::Error::RemoteStopped })
//    }
//}
//
//pub struct MockStarClient {
//    ac_client: Arc<dyn AdmissionControlClientTrait>,
//    node_handle: StarHandle,
//}
//
//impl MockStarClient {
//    pub fn new() -> Self {
//        let (mut config, _logger, _args) = setup_executable(
//            "Mock star single node".to_string(),
//            vec![ARG_PEER_ID, ARG_CONFIG_PATH, ARG_DISABLE_LOGGING],
//        );
//        if config.consensus.get_consensus_peers().len() == 0 {
//            let (_, single_peer_consensus_config) = ConfigHelpers::get_test_consensus_config(1, None);
//            config.consensus.consensus_peers = single_peer_consensus_config;
//        }
//
//        let genesis_path = genesis_blob();
//        config.execution.genesis_file_location = genesis_path;
//        let (ac_client, node_handle) = setup_environment(&mut config);
//        MockStarClient { ac_client, node_handle }
//    }
//}
//
//impl ChainClient for MockStarClient {
//    type WatchResp = MockStreamReceiver<WatchData>;
//
//    fn get_account_state_with_proof(&self, address: &AccountAddress, version: Option<Version>)
//                                    -> Result<(Version, Option<Vec<u8>>, SparseMerkleProof)> {
//        unimplemented!()
//    }
//
//    fn faucet(&self, address: AccountAddress, amount: u64) -> Result<()> {
//        unimplemented!()
//    }
//    fn submit_transaction(&self, signed_transaction: SignedTransaction) -> Result<()> {
//        unimplemented!()
//    }
//    fn watch_transaction(&self, address: &AccountAddress, ver: Version) -> Result<WatchStream<Self::WatchResp>> {
//        unimplemented!()
//    }
//    fn get_transaction_by_seq_num(&self, address: &AccountAddress, seq_num: u64) -> Result<Option<SignedTransactionWithProof>> {
//        unimplemented!()
//    }
//}