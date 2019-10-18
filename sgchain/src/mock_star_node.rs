// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use std::{
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use std::collections::{BTreeMap, HashSet};

use futures::{future, StreamExt};
use futures::executor::block_on;
use tokio::timer::Interval;

use admission_control_proto::proto::admission_control::{SubmitTransactionRequest, SubmitTransactionResponse};
use admission_control_service::{
    admission_control_service::AdmissionControlService,
};
use config::config::NodeConfig;
use crypto::{hash::GENESIS_BLOCK_ID, HashValue};
use executor::Executor;
use grpc_helpers::ServerHandle;
use libra_mempool::{
    core_mempool_client::CoreMemPoolClient,
};
use libra_types::crypto_proxies::LedgerInfoWithSignatures;
use libra_types::ledger_info::LedgerInfo;
use logger::prelude::*;
use storage_client::{StorageRead, StorageWrite};
use storage_service::start_storage_service_and_return_service;
use vm_runtime::MoveVM;
use vm_validator::vm_validator::VMValidator;
use futures::channel::{oneshot, mpsc};
use futures::channel::oneshot::Sender;
use libra_types::transaction::Transaction;

pub struct StarHandle {
    _storage: ServerHandle,
}

fn setup_ac<R>(
    config: &NodeConfig,
    r: Arc<R>,
    upstream_proxy_sender: mpsc::UnboundedSender<(
        SubmitTransactionRequest,
        oneshot::Sender<failure::Result<SubmitTransactionResponse>>,
    )>
) -> (
    CoreMemPoolClient,
    AdmissionControlService<CoreMemPoolClient, VMValidator>,
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
        upstream_proxy_sender
    );

    (mempool, handle)
}

fn setup_executor<R, W>(config: &NodeConfig, r: Arc<R>, w: Arc<W>) -> Arc<Executor<MoveVM>>
    where
        R: StorageRead + 'static,
        W: StorageWrite + 'static,
{
    Arc::new(Executor::new(
        r,
        w,
        config,
    ))
}


pub fn setup_environment(
    node_config: &mut NodeConfig,
) -> (
    StarHandle,
    Sender<()>,
    AdmissionControlService<CoreMemPoolClient, VMValidator>,
) {
    crash_handler::setup_panic_handler();

    let mut instant = Instant::now();
    let (storage, storage_service) = start_storage_service_and_return_service(&node_config);
    debug!(
        "Storage service started in {} ms",
        instant.elapsed().as_millis()
    );

    instant = Instant::now();
    let executor = setup_executor(
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
    let (upstream_proxy_sender, _upstream_proxy_receiver) = mpsc::unbounded();
    let (mempool_client, ac) = setup_ac(&node_config, Arc::clone(&storage_service), upstream_proxy_sender);
    debug!("AC started in {} ms", instant.elapsed().as_millis());

    let block_hash_vec = Mutex::new(vec![*GENESIS_BLOCK_ID]);

    let shutdown_sender = commit_block(block_hash_vec, mempool_client, executor);
    let star_handle = StarHandle { _storage: storage };

    (star_handle, shutdown_sender, ac)
}

fn commit_block(
    block_hash_vec: Mutex<Vec<HashValue>>,
    mempool_client: CoreMemPoolClient,
    executor: Arc<Executor<MoveVM>>,
) -> Sender<()> {
    let (shutdown_sender, mut shutdown_receiver) = oneshot::channel::<()>();

    let task = Interval::new(Instant::now(), Duration::from_secs(3))
        .take_while(move |_| {
            match shutdown_receiver.try_recv() {
                Err(_)| Ok(Some(_)) => {
                    info!("Build block task exit.");
                    future::ready(false)
                }
                _ => future::ready(true)
            }
        })
        .for_each(move |_| {
            let txns = mempool_client.get_block(1, HashSet::new());
            //debug!("for_each");
            debug!("txn size: {:?} of current block.", txns.len());

            if txns.len() > 0 {
                let block_id = HashValue::random();

                let len = block_hash_vec.lock().unwrap().len();
                let latest_hash = block_hash_vec.lock().unwrap().get(len - 1).unwrap().clone();
                debug!("block height: {:?}, new block hash: {:?}", len, latest_hash);
                let exclude_transactions = txns.iter().map(|txn| (txn.sender(), txn.sequence_number())).collect();
                let resp = block_on(executor.execute_block(txns.iter().map(|txn|Transaction::UserTransaction(txn.clone())).collect(), latest_hash, block_id)).unwrap().unwrap();

                block_hash_vec.lock().unwrap().push(block_id);

                // commit
                let info = LedgerInfo::new(resp.version(), resp.root_hash(), HashValue::random(), block_id, 0, u64::max_value(), None);
                let info_sign = LedgerInfoWithSignatures::new(info, BTreeMap::new());

                block_on(executor.commit_block(info_sign)).unwrap().unwrap();

                // remove from mem pool
                mempool_client.remove_txn(exclude_transactions);
            }
            future::ready(())
        });

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.spawn(task);
        rt.shutdown_on_idle();
    });

    shutdown_sender
}
