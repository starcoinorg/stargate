use crate::star_chain_client::gen_node_config_with_genesis;
use crate::star_chain_client::{faucet_async, submit_txn_async, ChainClient, StarChainClient};
use admission_control_service::runtime::AdmissionControlRuntime;
//use anyhow::{ensure};
use anyhow::Result;
use async_std::task;
use consensus::consensus_provider::make_pow_consensus_provider;
use consensus::{MineClient, MinerConfig};
use futures::channel::oneshot::{channel, Sender};
use futures::{future, StreamExt};
use grpc_helpers::ServerHandle;
use libra_config::config::{NetworkConfig, NodeConfig, RoleType};
use libra_crypto::traits::Uniform;
use libra_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    test_utils::KeyPair,
};
use libra_logger::prelude::*;
use libra_mempool::MempoolRuntime;
use libra_node::main_node::{setup_debug_interface, setup_executor, LibraHandle};
use libra_types::account_address::AccountAddress;
use libra_types::account_config::association_address;
use libra_types::transaction::{RawTransaction, SignedTransaction};
use network::{
    validator_network::{
        network_builder::{NetworkBuilder, TransportType},
        LibraNetworkProvider,
        // when you add a new protocol const, you must add this in either
        // .direct_send_protocols or .rpc_protocols vector of network_builder in setup_network()
        ADMISSION_CONTROL_RPC_PROTOCOL,
        CHAIN_STATE_DIRECT_SEND_PROTOCOL,
        CONSENSUS_DIRECT_SEND_PROTOCOL,
        CONSENSUS_RPC_PROTOCOL,
        MEMPOOL_DIRECT_SEND_PROTOCOL,
        STATE_SYNCHRONIZER_DIRECT_SEND_PROTOCOL,
    },
    ProtocolId,
};
use rand::prelude::*;
use rand::{rngs::StdRng, SeedableRng};
//use rusty_fork::{rusty_fork_id, rusty_fork_test, rusty_fork_test_name};
use state_synchronizer::StateSynchronizer;
use std::collections::HashMap;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use storage_service::start_storage_service;
use tokio::runtime::{Builder, Handle, Runtime};
use tokio::time::{interval, interval_at, Instant};
use transaction_builder::{encode_create_account_script, encode_transfer_script};
use vm_genesis::GENESIS_KEYPAIR;

pub fn setup_network(
    config: &mut NetworkConfig,
    role: RoleType,
) -> (Runtime, Box<dyn LibraNetworkProvider>) {
    let runtime = Builder::new()
        .thread_name("network-")
        .threaded_scheduler()
        .enable_all()
        .build()
        .expect("Failed to start runtime. Won't be able to start networking.");
    let mut network_builder = NetworkBuilder::new(
        runtime.handle().clone(),
        config.peer_id,
        config.listen_address.clone(),
        role,
    );
    network_builder
        .permissioned(config.is_permissioned)
        .advertised_address(config.advertised_address.clone())
        .direct_send_protocols(vec![
            ProtocolId::from_static(CONSENSUS_DIRECT_SEND_PROTOCOL),
            ProtocolId::from_static(MEMPOOL_DIRECT_SEND_PROTOCOL),
            ProtocolId::from_static(STATE_SYNCHRONIZER_DIRECT_SEND_PROTOCOL),
            ProtocolId::from_static(CHAIN_STATE_DIRECT_SEND_PROTOCOL),
        ])
        .rpc_protocols(vec![
            ProtocolId::from_static(CONSENSUS_RPC_PROTOCOL),
            ProtocolId::from_static(ADMISSION_CONTROL_RPC_PROTOCOL),
        ])
        .public(config.is_public_network);

    let seed_peers = config.seed_peers.seed_peers.clone();
    let signing_private = config
        .network_keypairs
        .signing_keys
        .take_private()
        .expect("Failed to take Network signing private key, key absent or already read");
    let signing_public = config.network_keypairs.signing_keys.public().clone();
    let identity_private = config
        .network_keypairs
        .identity_keys
        .take_private()
        .expect("Failed to take Network identity private key, key absent or already read");
    let identity_public = config.network_keypairs.identity_keys.public().clone();
    let trusted_peers = HashMap::new();

    network_builder
        .transport(TransportType::PermissionlessMemoryNoise(Some((
            identity_private,
            identity_public,
        ))))
        .connectivity_check_interval_ms(config.connectivity_check_interval_ms)
        .seed_peers(seed_peers)
        .trusted_peers(trusted_peers)
        .signing_keys((signing_private, signing_public))
        .discovery_interval_ms(config.discovery_interval_ms);

    let (_listen_addr, network_provider) = network_builder.build();
    (runtime, network_provider)
}

pub fn setup_environment(node_config: &mut NodeConfig, rollback_flag: bool) -> LibraHandle {
    crash_handler::setup_panic_handler();
    let miner_rpc_addr = node_config.consensus.miner_rpc_address.clone();
    task::spawn(async move {
        let mut miner_config = MinerConfig::default();
        miner_config.miner_server_addr = miner_rpc_addr;
        let mine_client = MineClient::new(miner_config);
        mine_client.start().await
    });
    let mut instant = Instant::now();
    let storage = start_storage_service(&node_config);
    debug!(
        "Storage service started in {} ms",
        instant.elapsed().as_millis()
    );

    instant = Instant::now();
    let executor = setup_executor(&node_config);
    debug!("Executor setup in {} ms", instant.elapsed().as_millis());
    let mut network_runtimes = vec![];
    let mut state_sync_network_handles = vec![];
    let mut ac_network_sender = None;
    let mut ac_network_events = vec![];
    let mut validator_network_provider = None;

    if let Some(network) = node_config.validator_network.as_mut() {
        let (runtime, mut network_provider) = setup_network(network, RoleType::Validator);
        state_sync_network_handles.push(network_provider.add_state_synchronizer(vec![
            ProtocolId::from_static(STATE_SYNCHRONIZER_DIRECT_SEND_PROTOCOL),
        ]));

        let (ac_sender, ac_events) =
            network_provider.add_admission_control(vec![ProtocolId::from_static(
                ADMISSION_CONTROL_RPC_PROTOCOL,
            )]);
        ac_network_events.push(ac_events);

        validator_network_provider = Some((network.peer_id, runtime, network_provider));
        ac_network_sender = Some(ac_sender);
    }

    let debug_if = ServerHandle::setup(setup_debug_interface(&node_config));

    let state_synchronizer = StateSynchronizer::bootstrap(
        state_sync_network_handles,
        Arc::clone(&executor),
        &node_config,
    );
    let admission_control = AdmissionControlRuntime::bootstrap(
        &node_config,
        ac_network_sender.unwrap(),
        ac_network_events,
    );

    let mut mempool = None;
    let mut consensus = None;
    let (mut _cs_network_sender, mut _cs_network_events) = (None, None);
    if let Some((peer_id, runtime, mut network_provider)) = validator_network_provider {
        let (mempool_network_sender, mempool_network_events) = network_provider
            .add_mempool(vec![ProtocolId::from_static(MEMPOOL_DIRECT_SEND_PROTOCOL)]);
        let (consensus_network_sender, consensus_network_events) =
            network_provider.add_consensus(vec![
                ProtocolId::from_static(CONSENSUS_RPC_PROTOCOL),
                ProtocolId::from_static(CONSENSUS_DIRECT_SEND_PROTOCOL),
            ]);
        //add chain state protocol
        let (chain_state_network_sender, chain_state_network_events) = network_provider
            .add_chain_state(vec![ProtocolId::from_static(
                CHAIN_STATE_DIRECT_SEND_PROTOCOL,
            )]);

        _cs_network_sender = Some(chain_state_network_sender);
        _cs_network_events = Some(chain_state_network_events);

        runtime.handle().clone().spawn(network_provider.start());
        network_runtimes.push(runtime);
        debug!("Network started for peer_id: {}", peer_id);

        // Initialize and start mempool.
        instant = Instant::now();
        mempool = Some(MempoolRuntime::bootstrap(
            &node_config,
            mempool_network_sender,
            mempool_network_events,
        ));
        debug!("Mempool started in {} ms", instant.elapsed().as_millis());

        // Initialize and start consensus.
        instant = Instant::now();
        let mut consensus_provider = make_pow_consensus_provider(
            node_config,
            consensus_network_sender,
            consensus_network_events,
            executor,
            state_synchronizer.create_client(),
            rollback_flag,
            _cs_network_sender.expect("cs_network_sender is none."),
            _cs_network_events.expect("cs_network_events is none."),
        );
        consensus_provider
            .start()
            .expect("Failed to start consensus. Can't proceed.");
        consensus = Some(consensus_provider);
        debug!("Consensus started in {} ms", instant.elapsed().as_millis());
    }

    LibraHandle {
        _network_runtimes: network_runtimes,
        _ac: admission_control,
        _mempool: mempool,
        _state_synchronizer: state_synchronizer,
        consensus,
        _storage: storage,
        _debug: debug_if,
    }
}

fn print_ports(config: &NodeConfig) {
    debug!(
        "{}",
        config.admission_control.admission_control_service_port
    );
    debug!(
        "{}",
        config.debug_interface.admission_control_node_debug_port
    );
    debug!("{}", config.debug_interface.metrics_server_port);
    debug!("{}", config.debug_interface.storage_node_debug_port);
    debug!("{}", config.execution.port);
    debug!("{}", config.mempool.mempool_service_port);
    debug!("{}", config.storage.port);
}

//rusty_fork_test! {
//    #[test]
//    fn test_pow_with_fork() {
//        _test_pow_node().unwrap();
//    }
//}

fn _test_pow_node() -> Result<()> {
    ::libra_logger::init_for_e2e_testing();
    let memory_address = "/memory/0";
    let mut conf_1 = gen_node_config_with_genesis(1, true, true, Some(memory_address), false);
    let (peer_1, peer_info_1) = conf_1.validator_network.as_ref().unwrap().get_peer_info();
    let mut conf_2 = gen_node_config_with_genesis(2, true, true, Some(memory_address), false);
    let (peer_2, peer_info_2) = conf_2.validator_network.as_ref().unwrap().get_peer_info();
    conf_1
        .validator_network
        .as_mut()
        .unwrap()
        .add_peer(peer_2, peer_info_2);
    conf_2
        .validator_network
        .as_mut()
        .unwrap()
        .add_peer(peer_1, peer_info_1);
    conf_2
        .validator_network
        .as_mut()
        .unwrap()
        .add_seed(peer_1, "/memory/1");
    print_ports(&conf_1);
    debug!("conf1:{:?}", conf_1);
    debug!("conf2:{:?}", conf_2);
    let _handle_1 = setup_environment(&mut conf_1, false);

    let mut runtime_1 = tokio::runtime::Runtime::new().unwrap();
    sleep(Duration::from_secs(20));
    let _handle_2 = setup_environment(&mut conf_2, false);
    let runtime_2 = tokio::runtime::Runtime::new().unwrap();

    print_ports(&conf_2);
    let flag = false;

    let (s1, s2) = if flag {
        let s1 = commit_tx(
            conf_1.admission_control.admission_control_service_port as u32,
            runtime_1.handle().clone(),
        );

        sleep(Duration::from_secs(30));

        let s2 = commit_tx(
            conf_2.admission_control.admission_control_service_port as u32,
            runtime_2.handle().clone(),
        );

        (s1, s2)
    } else {
        let account_keypair_1: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> = _create_keypair();
        let account_keypair_2: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> = _create_keypair();

        let faucet_1 = _faucet_txn(
            AccountAddress::from_public_key(&account_keypair_1.public_key),
            1,
        );
        let faucet_2 = _faucet_txn(
            AccountAddress::from_public_key(&account_keypair_2.public_key),
            2,
        );

        let s1 = _commit_tx_2(
            conf_1.admission_control.admission_control_service_port as u32,
            runtime_1.handle().clone(),
            &faucet_2,
            (&faucet_1, account_keypair_1),
        );

        sleep(Duration::from_secs(30));

        let s2 = _commit_tx_2(
            conf_2.admission_control.admission_control_service_port as u32,
            runtime_2.handle().clone(),
            &faucet_1,
            (&faucet_2, account_keypair_2),
        );

        (s1, s2)
    };

    runtime_1.block_on(async {
        _check_latest_ledger(
            conf_1.admission_control.admission_control_service_port as u32,
            conf_2.admission_control.admission_control_service_port as u32,
            s1,
            s2,
        );
    });
    Ok(())
}

fn _create_keypair() -> KeyPair<Ed25519PrivateKey, Ed25519PublicKey> {
    let mut seed_rng = rand::rngs::OsRng::new().expect("can't access OsRng");
    let seed_buf: [u8; 32] = seed_rng.gen();
    let mut rng0: StdRng = SeedableRng::from_seed(seed_buf);
    KeyPair::generate_for_testing(&mut rng0)
}

#[test]
fn test_pow_single_node() {
    ::libra_logger::init_for_e2e_testing();
    let mut conf_1 = gen_node_config_with_genesis(1, true, true, Some("/memory/0"), false);
    print_ports(&conf_1);
    debug!("conf1:{:?}", conf_1);
    let _handle_1 = setup_environment(&mut conf_1, false);

    let mut runtime_1 = tokio::runtime::Runtime::new().unwrap();
    let s = commit_tx(
        conf_1.admission_control.admission_control_service_port as u32,
        runtime_1.handle().clone(),
    );

    runtime_1.block_on(async {
        check_single_latest_ledger(
            conf_1.admission_control.admission_control_service_port as u32,
            s,
            true,
        );
    });
}

#[test]
fn test_pow_block_tree() {
    ::libra_logger::init_for_e2e_testing();
    let template = gen_node_config_with_genesis(1, true, true, Some("/memory/0"), false);
    print_ports(&template);
    debug!("conf1:{:?}", template);
    let base_path = template.base.data_dir.clone();
    let _db_path = template.storage.dir.clone();
    let mut rng = StdRng::from_seed([0u8; 32]);
    for _i in 0..2 {
        let mut conf_1 = NodeConfig::random_with_template(&template, &mut rng);
        conf_1.set_data_dir(base_path.clone()).unwrap();
        let _handle_1 = setup_environment(&mut conf_1, false);

        let mut runtime_1 = tokio::runtime::Runtime::new().unwrap();
        let s = commit_tx(
            conf_1.admission_control.admission_control_service_port as u32,
            runtime_1.handle().clone(),
        );

        runtime_1.block_on(async {
            check_single_latest_ledger(
                conf_1.admission_control.admission_control_service_port as u32,
                s,
                true,
            );
        });

        drop(runtime_1);
        drop(_handle_1);

        sleep(Duration::from_secs(10));
    }
}

#[test]
fn test_pbft_single_node() {
    ::libra_logger::init_for_e2e_testing();
    let mut config = gen_node_config_with_genesis(1, true, false, None, true);
    print_ports(&config);
    debug!("conf1:{:?}", config);

    let _handler = libra_node::main_node::setup_environment(&mut config);

    let mut runtime_1 = tokio::runtime::Runtime::new().unwrap();
    let s = commit_tx(
        config.admission_control.admission_control_service_port as u32,
        runtime_1.handle().clone(),
    );

    runtime_1.block_on(async {
        check_single_latest_ledger(
            config.admission_control.admission_control_service_port as u32,
            s,
            false,
        );
    });
}

#[test]
fn test_validator_nodes() {
    let node_conf_1 = NodeConfig::random();
    let node_conf_2 = NodeConfig::random();
    println!("{:?}", node_conf_1);
    println!("{:?}", node_conf_2);
}

#[test]
fn test_rollback_block() {
    ::libra_logger::init_for_e2e_testing();
    let mut conf_1 = gen_node_config_with_genesis(1, true, true, Some("/memory/0"), false);
    print_ports(&conf_1);
    debug!("conf1:{:?}", conf_1);

    let _handle_1 = setup_environment(&mut conf_1, true);

    let mut runtime_1 = tokio::runtime::Runtime::new().unwrap();
    let s = commit_tx(
        conf_1.admission_control.admission_control_service_port as u32,
        runtime_1.handle().clone(),
    );

    runtime_1.block_on(async {
        check_single_latest_ledger(
            conf_1.admission_control.admission_control_service_port as u32,
            s,
            true,
        );
    });
}

#[test]
fn test_coin_base() {
    ::libra_logger::init_for_e2e_testing();
    let mut conf_1 = gen_node_config_with_genesis(1, true, true, Some("/memory/0"), false);

    let consensus_address = conf_1.consensus.consensus_keypair.consensus_address();
    let _handle_1 = setup_environment(&mut conf_1, false);

    sleep(Duration::from_secs(60));

    let client = StarChainClient::new(
        "127.0.0.1",
        conf_1.admission_control.admission_control_service_port as u32,
    );
    let account_state = client
        .get_account_state(consensus_address, None)
        .expect("get account state err.");
    let balance = account_state
        .get_account_resource()
        .expect("balance is none.")
        .balance();
    println!("address {:?} , balance :{}", consensus_address, balance);
    assert!(balance >= 50);
}

fn gen_account() -> AccountAddress {
    let mut seed_rng = rand::rngs::OsRng::new().expect("can't access OsRng");
    let seed_buf: [u8; 32] = seed_rng.gen();
    let mut rng0: StdRng = SeedableRng::from_seed(seed_buf);
    let account_keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> =
        KeyPair::generate_for_testing(&mut rng0);

    AccountAddress::from_public_key(&account_keypair.public_key)
}

fn _transfer(
    private_key: &Ed25519PrivateKey,
    public_key: Ed25519PublicKey,
    sequence_number: u64,
    recipient: &AccountAddress,
) -> SignedTransaction {
    let script = encode_transfer_script(recipient, 10);

    let sender = AccountAddress::from_public_key(&public_key);
    RawTransaction::new_script(
        sender.clone(),
        sequence_number,
        script,
        10_000 as u64,
        1 as u64,
        Duration::from_secs(u64::max_value()),
    )
    .sign(private_key, public_key)
    .unwrap()
    .into_inner()
}

fn _faucet_txn(receiver: AccountAddress, sequence_number: u64) -> SignedTransaction {
    let script = encode_create_account_script(&receiver, 10_000_000);
    let sender = association_address();
    RawTransaction::new_script(
        sender.clone(),
        sequence_number,
        script,
        1000_000 as u64,
        1 as u64,
        Duration::from_secs(u64::max_value()),
    )
    .sign(&GENESIS_KEYPAIR.0, GENESIS_KEYPAIR.1.clone())
    .unwrap()
    .into_inner()
}

fn _commit_tx_2(
    port: u32,
    executor: Handle,
    faucet: &SignedTransaction,
    owner: (
        &SignedTransaction,
        KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
    ),
) -> Sender<()> {
    let (shutdown_sender, mut shutdown_receiver) = channel::<()>();

    let faucet_executor = executor.clone();

    let client = StarChainClient::new("127.0.0.1", port);
    submit_txn_async(client.clone(), faucet_executor.clone(), faucet.clone());
    sleep(Duration::from_secs(10));
    submit_txn_async(client.clone(), faucet_executor.clone(), owner.0.clone());
    sleep(Duration::from_secs(10));
    let mut count = 0;
    let key_pair = owner.1;

    let f = async move {
        interval(Duration::from_secs(10))
            .take_while(move |_| match shutdown_receiver.try_recv() {
                Err(_) | Ok(Some(_)) => {
                    info!("Build block task exit.");
                    future::ready(false)
                }
                _ => future::ready(true),
            })
            .for_each(move |_| {
                let account = gen_account();
                let txn = _transfer(
                    &key_pair.private_key,
                    key_pair.public_key.clone(),
                    count,
                    &account,
                );
                submit_txn_async(client.clone(), faucet_executor.clone(), txn);
                count = count + 1;

                future::ready(())
            })
            .await;
    };

    executor.spawn(f);

    shutdown_sender
}

fn commit_tx(port: u32, executor: Handle) -> Sender<()> {
    let (shutdown_sender, mut shutdown_receiver) = channel::<()>();

    let account = gen_account();
    let faucet_executor = executor.clone();
    let f = async move {
        interval_at(Instant::now(), Duration::from_secs(10))
            .take_while(move |_| match shutdown_receiver.try_recv() {
                Err(_) | Ok(Some(_)) => {
                    info!("Build block task exit.");
                    future::ready(false)
                }
                _ => future::ready(true),
            })
            .for_each(move |_| {
                let client = StarChainClient::new("127.0.0.1", port.clone());
                faucet_async(client, faucet_executor.clone(), account, 10);
                future::ready(())
            })
            .await;
    };

    executor.spawn(f);

    shutdown_sender
}

fn _check_latest_ledger(port1: u32, port2: u32, sender_1: Sender<()>, sender_2: Sender<()>) {
    loop {
        sleep(Duration::from_secs(10));
        let client1 = StarChainClient::new("127.0.0.1", port1);
        let client2 = StarChainClient::new("127.0.0.1", port2);

        let ledger_1 = client1.get_latest_ledger(&association_address());
        let ledger_2 = client2.get_latest_ledger(&association_address());

        if ledger_1.version() > 15
            && ledger_2.version() > 15
            && ledger_1.version() == ledger_2.version()
        {
            assert_eq!(ledger_1.consensus_block_id(), ledger_2.consensus_block_id());
            sender_1.send(()).unwrap();
            sender_2.send(()).unwrap();
            break;
        } else {
            if ledger_1.version() > 30 || ledger_2.version() > 30 {
                assert!(false);
            }
        }
    }
}

fn check_single_latest_ledger(port: u32, sender: Sender<()>, pow_mode: bool) {
    let end_time = Instant::now() + Duration::from_secs(60 * 6);
    loop {
        sleep(Duration::from_secs(10));
        let client = StarChainClient::new("127.0.0.1", port);

        let ledger = client.get_latest_ledger(&association_address());
        if (ledger.version() > 15 && pow_mode) || (ledger.version() > 150 && !pow_mode) {
            assert!(true);
            sender.send(()).unwrap();
            break;
        }

        if Instant::now() >= end_time {
            assert!(false);
        }
    }
}
