// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use admission_control_service::admission_control_service::AdmissionControlService;
use admission_control_service::admission_control_client::AdmissionControlClient;
use config::config::{NodeConfig};
use crypto::{hash::GENESIS_BLOCK_ID, HashValue};
use execution_proto::proto::{
    execution::{CommitBlockRequest, ExecuteBlockRequest},
};
use execution_service::ExecutionService;
use futures::{
    future,
    sync::mpsc::{unbounded, UnboundedSender},
    Future, Stream,
};
use grpc_helpers::ServerHandle;
use logger::prelude::*;
use mempool::{
    core_mempool_client::CoreMemPoolClient,
    proto::{
        mempool::{GetBlockRequest, TransactionExclusion},
        mempool_client::MempoolClientTrait,
    },
};
use proto_conv::FromProto;
use std::{
    sync::{Arc, Mutex},
    thread::{self},
    time::{Duration, Instant},
};
use storage_client::{
    StorageRead, StorageWrite,
};
use storage_service::start_storage_service_and_return_service;
use tokio_timer::Interval;
use types::{
    proto::{
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
        validator_set::ValidatorSet,
    },
    transaction::{SignedTransaction},
};
use vm_validator::vm_validator::VMValidator;

pub struct StarHandle {
    _storage: ServerHandle,
}

fn setup_ac<R>(
    config: &NodeConfig,
    r: Arc<R>,
) -> (
    AdmissionControlClient<CoreMemPoolClient, VMValidator>,
    CoreMemPoolClient,
)
where
    R: StorageRead + Clone + 'static,
{
    let mempool = CoreMemPoolClient::new(&config);
    let mempool_client = Some(Arc::new(mempool.clone()));

    let storage_read_client = Arc::clone(&r);
    let vm_validator = Arc::new(VMValidator::new(&config, storage_read_client));

    let storage_read_client = Arc::clone(&r);
    let handle = AdmissionControlService::new(
        mempool_client,
        storage_read_client,
        vm_validator,
        config
            .admission_control
            .need_to_check_mempool_before_validation,
    );

    (AdmissionControlClient::new(handle), mempool)
}

fn setup_executor<R, W>(config: &NodeConfig, r: Arc<R>, w: Arc<W>) -> ExecutionService
where
    R: StorageRead + 'static,
    W: StorageWrite + 'static,
{
    ExecutionService::new(r, w, config)
}

pub fn setup_environment(
    node_config: &mut NodeConfig,
) -> (
    AdmissionControlClient<CoreMemPoolClient, VMValidator>,
    StarHandle,
    UnboundedSender<()>,
) {
    crash_handler::setup_panic_handler();

    let mut instant = Instant::now();
    let (storage, storage_service) = start_storage_service_and_return_service(&node_config);
    debug!(
        "Storage service started in {} ms",
        instant.elapsed().as_millis()
    );

    instant = Instant::now();
    let execution_service = setup_executor(
        &node_config,
        Arc::clone(&storage_service),
        Arc::clone(&storage_service),
    );
    debug!(
        "Execution service started in {} ms",
        instant.elapsed().as_millis()
    );

    // Initialize and start AC.
    instant = Instant::now();
    let (ac_client, mempool_client) = setup_ac(&node_config, Arc::clone(&storage_service));
    debug!("AC started in {} ms", instant.elapsed().as_millis());

    let block_hash_vec = Mutex::new(vec![*GENESIS_BLOCK_ID]);

    let shutdown_sender = commit_block(
        block_hash_vec,
        mempool_client,
        execution_service,
    );
    let star_handle = StarHandle { _storage: storage };

    (ac_client, star_handle, shutdown_sender)
}

fn commit_block(
    block_hash_vec: Mutex<Vec<HashValue>>,
    mempool_client: CoreMemPoolClient,
    execution_service: ExecutionService,
) -> UnboundedSender<()> {
    let (shutdown_sender, mut shutdown_receiver) = unbounded();

    let task = Interval::new(Instant::now(), Duration::from_secs(3))
        .take_while(move |_| {
            match shutdown_receiver.poll() {
                Ok(opt) => match opt {
                    futures::Async::Ready(_shutdown) => {
                        info!("Build block task exit.");
                        return future::ok(false);
                    }
                    _ => {}
                },
                _ => {}
            }
            return future::ok(true);
        })
        .for_each(move |_| {
            let mut block_req = GetBlockRequest::new();
            block_req.set_max_block_size(1);
            let block_resp = mempool_client
                .get_block(&block_req)
                .expect("get_block err.");
            let block = block_resp.get_block();
            let txns = block.get_transactions();

            debug!("txn size: {:?} of current block.", txns.len());

            if txns.len() > 0 {
                let mut tmp_txn_vec = vec![];
                let mut txn_exc_vec = vec![];
                txns.clone().iter().for_each(|txn| {
                    let tmp = SignedTransaction::from_proto(txn.clone()).expect("from pb err.");

                    let mut txn_exc = TransactionExclusion::new();
                    txn_exc.set_sender(tmp.sender().to_vec());
                    txn_exc.set_sequence_number(tmp.sequence_number());
                    txn_exc_vec.push(txn_exc);

                    tmp_txn_vec.push(tmp);
                });

                // exe
                let repeated = ::protobuf::RepeatedField::from_vec(txns.to_vec());
                let mut exe_req = ExecuteBlockRequest::new();
                let block_id = HashValue::random();
                exe_req.set_transactions(repeated);

                let len = block_hash_vec.lock().unwrap().len();
                let latest_hash = block_hash_vec.lock().unwrap().get(len - 1).unwrap().clone();
                debug!("block height: {:?}, new block hash: {:?}", len, latest_hash);

                exe_req.set_parent_block_id(latest_hash.to_vec());

                exe_req.set_block_id(block_id.to_vec());
                let exe_resp = execution_service.execute_block_inner(exe_req.clone());

                block_hash_vec.lock().unwrap().push(block_id);

                // commit
                let mut info = LedgerInfo::new();
                info.set_version(exe_resp.get_version());
                info.set_consensus_block_id(exe_req.get_block_id().to_vec());
                info.set_consensus_data_hash(HashValue::random().to_vec());
                info.set_epoch_num(0);
                info.set_next_validator_set(ValidatorSet::default());
                info.set_timestamp_usecs(u64::max_value());
                info.set_transaction_accumulator_hash(exe_resp.get_root_hash().to_vec());
                let mut info_sign = LedgerInfoWithSignatures::new();
                //        exe_resp.get_validators()
                //        info.set_signatures()
                info_sign.set_ledger_info(info);
                let mut req = CommitBlockRequest::new();
                req.set_ledger_info_with_sigs(info_sign.clone());
                execution_service.commit_block_inner(req);

                // remove from mem pool
                let mut remove_req = GetBlockRequest::new();

                let repeated_txn_exc = ::protobuf::RepeatedField::from_vec(txn_exc_vec);
                remove_req.set_transactions(repeated_txn_exc);

                mempool_client.remove_txn(&remove_req);
            }
            Ok(())
        })
        .map_err(|e| warn!("interval errored; err={:?}", e));

    thread::spawn(move || {
        //        let mut rt = tokio::runtime::Runtime::new().unwrap();
        //        let executor = rt.executor();
        //        executor.spawn(task);
        //        rt.shutdown_on_idle().wait().unwrap();

        tokio::run(task)
    });

    shutdown_sender
}
