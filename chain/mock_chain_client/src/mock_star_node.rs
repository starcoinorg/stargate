// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use admission_control_proto::proto::admission_control_grpc::create_admission_control;
use admission_control_service::{admission_control_service::AdmissionControlService,
                                admission_control_client::AdmissionControlClient};
use config::config::{NetworkConfig, NodeConfig, RoleType};
use crypto::{ed25519::*, ValidKey};
use execution_proto::proto::execution_grpc;
use execution_service::ExecutionService;
use futures03::future::{FutureExt, TryFutureExt};
use grpc_helpers::ServerHandle;
use grpcio::{ChannelBuilder, EnvBuilder, ServerBuilder};
use grpcio_sys;
use logger::prelude::*;
use mempool::{proto::{mempool_grpc::MempoolClient, core_mempool_client::CoreMemPoolClient}, MempoolRuntime};
use metrics::metric_server;
use std::{
    cmp::min,
    convert::{TryFrom, TryInto},
    str::FromStr,
    sync::Arc,
    thread,
    time::Instant,
};
use storage_client::{StorageRead, StorageWrite, StorageReadServiceClient, StorageWriteServiceClient};
use storage_service::start_storage_service_and_return_service;
use tokio::runtime::{Builder, Runtime};
use types::account_address::AccountAddress as PeerId;
use vm_validator::vm_validator::VMValidator;

pub struct StarHandle {
    _execution: ServerHandle,
    _storage: ServerHandle,
}

fn setup_ac<R>(config: &NodeConfig, r: Arc<R>) -> AdmissionControlClient<CoreMemPoolClient, VMValidator> where R: StorageRead + Clone + 'static {
    let env = Arc::new(
        EnvBuilder::new()
            .name_prefix("grpc-ac-")
            .cq_count(unsafe { min(grpcio_sys::gpr_cpu_num_cores() as usize * 2, 32) })
            .build(),
    );
    let port = config.admission_control.admission_control_service_port;

    let mempool_client = Some(Arc::new(CoreMemPoolClient::new(&config)));

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

    AdmissionControlClient::new(handle)
}

fn setup_executor<R, W>(config: &NodeConfig, r: Arc<R>, w: Arc<W>) -> ::grpcio::Server where R: StorageRead + 'static, W: StorageWrite + 'static {
    let client_env = Arc::new(EnvBuilder::new().name_prefix("grpc-exe-sto-").build());

    let handle = ExecutionService::new(r, w, config);
    let service = execution_grpc::create_execution(handle);
    ::grpcio::ServerBuilder::new(Arc::new(EnvBuilder::new().name_prefix("grpc-exe-").build()))
        .register_service(service)
        .bind(config.execution.address.clone(), config.execution.port)
        .build()
        .expect("Unable to create grpc server")
}

pub fn setup_environment(node_config: &mut NodeConfig) -> (AdmissionControlClient<CoreMemPoolClient, VMValidator>, StarHandle) {
    crash_handler::setup_panic_handler();

    // Some of our code uses the rayon global thread pool. Name the rayon threads so it doesn't
    // cause confusion, otherwise the threads would have their parent's name.
    rayon::ThreadPoolBuilder::new()
        .thread_name(|index| format!("rayon-global-{}", index))
        .build_global()
        .expect("Building rayon global thread pool should work.");

    let mut instant = Instant::now();
    let (storage, storage_service) = start_storage_service_and_return_service(&node_config);
    debug!(
        "Storage service started in {} ms",
        instant.elapsed().as_millis()
    );

    instant = Instant::now();
    let execution = ServerHandle::setup(setup_executor(&node_config, Arc::clone(&storage_service), Arc::clone(&storage_service)));
    debug!(
        "Execution service started in {} ms",
        instant.elapsed().as_millis()
    );

    let metrics_port = node_config.debug_interface.metrics_server_port;
    let metric_host = node_config.debug_interface.address.clone();
    thread::spawn(move || metric_server::start_server((metric_host.as_str(), metrics_port)));

    // Initialize and start AC.
    instant = Instant::now();
    let ac_client = setup_ac(&node_config, Arc::clone(&storage_service));
    debug!("AC started in {} ms", instant.elapsed().as_millis());

    let star_handle = StarHandle {
        _execution: execution,
        _storage: storage,
    };
    (ac_client, star_handle)
}