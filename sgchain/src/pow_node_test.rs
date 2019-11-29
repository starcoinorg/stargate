// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::star_chain_client::{faucet_async, submit_txn_async, ChainClient, StarChainClient};
use admission_control_service::runtime::AdmissionControlRuntime;
use async_std::task;
use consensus::consensus_provider::make_pow_consensus_provider;
use consensus::MineClient;
use futures::channel::oneshot::{channel, Sender};
use futures::future;
use futures::StreamExt;
use grpc_helpers::ServerHandle;
use libra_config::config::{ConsensusType, NetworkConfig, NodeConfig, NodeConfigHelpers, RoleType};
use libra_config::{
    seed_peers::SeedPeersConfig,
    trusted_peers::{ConfigHelpers, ConsensusPeerInfo, NetworkPeerInfo},
};
use libra_crypto::test_utils::TEST_SEED;
use libra_crypto::traits::Uniform;
use libra_crypto::ValidKey;
use libra_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    test_utils::KeyPair,
};
use libra_logger::prelude::*;
use libra_mempool::MempoolRuntime;
use libra_node::main_node::{setup_debug_interface, setup_executor, LibraHandle};
use libra_types::account_address::{AccountAddress as PeerId, AccountAddress};
use libra_types::account_config::association_address;
use libra_types::transaction::{RawTransaction, SignedTransaction};
use network::{
    validator_network::{
        network_builder::{NetworkBuilder, TransportType},
        LibraNetworkProvider,
        // when you add a new protocol const, you must add this in either
        // .direct_send_protocols or .rpc_protocols vector of network_builder in setup_network()
        ADMISSION_CONTROL_RPC_PROTOCOL,
        CONSENSUS_DIRECT_SEND_PROTOCOL,
        CONSENSUS_RPC_PROTOCOL,
        MEMPOOL_DIRECT_SEND_PROTOCOL,
        STATE_SYNCHRONIZER_DIRECT_SEND_PROTOCOL,
    },
    NetworkPublicKeys, ProtocolId,
};
use parity_multiaddr::Multiaddr;
use rand::prelude::*;
use rand::{rngs::StdRng, SeedableRng};
use state_synchronizer::StateSynchronizer;
use std::collections::HashMap;
use std::thread::sleep;
use std::time::Duration;
use std::{
    convert::{TryFrom, TryInto},
    str::FromStr,
    sync::Arc,
    time::Instant,
};
use storage_service::start_storage_service;
use tokio::runtime::TaskExecutor;
use tokio::runtime::{Builder, Runtime};
use tokio::timer::Interval;
use transaction_builder::{encode_create_account_script, encode_transfer_script};
use vm_genesis::GENESIS_KEYPAIR;

pub fn setup_network(
    peer_id: PeerId,
    config: &mut NetworkConfig,
) -> (Runtime, Box<dyn LibraNetworkProvider>) {
    let runtime = Builder::new()
        .name_prefix("pow-network-")
        .build()
        .expect("Failed to start runtime. Won't be able to start networking.");
    let role: RoleType = config.role;
    let mut network_builder = NetworkBuilder::new(
        runtime.executor(),
        peer_id,
        config.listen_address.clone(),
        role,
    );
    network_builder
        .permissioned(config.is_permissioned)
        .is_public(config.is_public_network)
        .advertised_address(config.listen_address.clone())
        .direct_send_protocols(vec![
            ProtocolId::from_static(CONSENSUS_DIRECT_SEND_PROTOCOL),
            ProtocolId::from_static(MEMPOOL_DIRECT_SEND_PROTOCOL),
            ProtocolId::from_static(STATE_SYNCHRONIZER_DIRECT_SEND_PROTOCOL),
        ])
        .rpc_protocols(vec![
            ProtocolId::from_static(CONSENSUS_RPC_PROTOCOL),
            ProtocolId::from_static(ADMISSION_CONTROL_RPC_PROTOCOL),
        ]);

    let trusted_peers = config
        .network_peers
        .peers
        .iter()
        .map(|(peer_id, keys)| {
            (
                PeerId::from_str(peer_id).unwrap(),
                NetworkPublicKeys {
                    signing_public_key: keys.network_signing_pubkey.clone(),
                    identity_public_key: keys.network_identity_pubkey.clone(),
                },
            )
        })
        .collect();

    let seed_peers = config
        .seed_peers
        .seed_peers
        .clone()
        .into_iter()
        .map(|(peer_id, addrs)| {
            let tmp = peer_id.try_into().expect("Invalid PeerId");
            (tmp, addrs)
        })
        .collect();

    let network_signing_private_key = config
        .network_keypairs
        .take_network_signing_private()
        .unwrap();
    let network_signing_public_key = config.network_keypairs.get_network_signing_public_key();
    network_builder
        .seed_peers(seed_peers)
        .trusted_peers(trusted_peers)
        .signing_keys((network_signing_private_key, network_signing_public_key));

    network_builder.transport(TransportType::PermissionlessMemoryNoise(Some((
        config.network_keypairs.get_network_identity_private(),
        config
            .network_keypairs
            .get_network_identity_public()
            .clone(),
    ))));

    let (_listen_addr, network_provider) = network_builder.build();
    (runtime, network_provider)
}

pub fn setup_environment(node_config: &mut NodeConfig, rollback_flag: bool) -> LibraHandle {
    crash_handler::setup_panic_handler();
    let miner_rpc_addr = node_config.consensus.miner_rpc_address.clone();
    task::spawn(async move {
        let mine_client = MineClient::new(miner_rpc_addr);
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

    for i in 0..node_config.networks.len() {
        let peer_id =
            PeerId::try_from(node_config.networks[i].peer_id.clone()).expect("Invalid PeerId");
        let (runtime, mut network_provider) = setup_network(peer_id, &mut node_config.networks[i]);
        state_sync_network_handles.push(network_provider.add_state_synchronizer(vec![
            ProtocolId::from_static(STATE_SYNCHRONIZER_DIRECT_SEND_PROTOCOL),
        ]));

        let (ac_sender, ac_events) =
            network_provider.add_admission_control(vec![ProtocolId::from_static(
                ADMISSION_CONTROL_RPC_PROTOCOL,
            )]);
        ac_network_events.push(ac_events);

        let network = &node_config.networks[i];
        if network.role == RoleType::Validator {
            validator_network_provider = Some((peer_id, runtime, network_provider));
            ac_network_sender = Some(ac_sender);
        } else {
            if node_config.is_upstream_network(network) {
                ac_network_sender = Some(ac_sender);
            }
            // For non-validator roles, the peer_id should be derived from the network identity
            // key.
            assert_eq!(
                peer_id,
                PeerId::try_from(
                    network
                        .network_keypairs
                        .get_network_identity_public()
                        .to_bytes()
                )
                .unwrap()
            );
            // Start the network provider.
            runtime.executor().spawn(network_provider.start());
            network_runtimes.push(runtime);
            debug!("Network started for peer_id: {}", peer_id);
        }
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
    if let Some((peer_id, runtime, mut network_provider)) = validator_network_provider {
        let (mempool_network_sender, mempool_network_events) = network_provider
            .add_mempool(vec![ProtocolId::from_static(MEMPOOL_DIRECT_SEND_PROTOCOL)]);
        let (consensus_network_sender, consensus_network_events) =
            network_provider.add_consensus(vec![
                ProtocolId::from_static(CONSENSUS_RPC_PROTOCOL),
                ProtocolId::from_static(CONSENSUS_DIRECT_SEND_PROTOCOL),
            ]);
        runtime.executor().spawn(network_provider.start());
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

fn node_random_conf(pow_mode: bool, listen_address: &str, times: usize) -> NodeConfig {
    let mut config = NodeConfigHelpers::get_single_node_test_config_times(true, times);

    if pow_mode {
        for conf in &mut (&mut config).networks {
            conf.is_permissioned = false;
            conf.is_public_network = true;
            conf.enable_encryption_and_authentication = true;
            conf.listen_address = listen_address.parse().unwrap();
            conf.role = RoleType::Validator;
        }
    }

    debug!("config : {:?}", config);
    crate::star_chain_client::genesis_blob(&config);

    config
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

#[test]
fn test_pow_node() {
    ::libra_logger::init_for_e2e_testing();
    let mut conf_1 = node_random_conf(true, "/memory/0", 0);
    let mut conf_2 = node_random_conf(true, "/memory/0", 1);

    let network_signing_public_key_1: Ed25519PublicKey = conf_1.networks[0]
        .network_keypairs
        .get_network_signing_public_key();
    let network_signing_public_key_2: Ed25519PublicKey = conf_2.networks[0]
        .network_keypairs
        .get_network_signing_public_key();
    let network_identity_pubkey_key_1 = conf_1.networks[0]
        .network_keypairs
        .get_network_identity_public()
        .clone();
    let network_identity_pubkey_key_2 = conf_2.networks[0]
        .network_keypairs
        .get_network_identity_public()
        .clone();

    // consensus peers
    let consensus_peers: HashMap<_, _> = vec![
        (
            conf_1.networks[0].peer_id.clone(),
            ConsensusPeerInfo {
                consensus_pubkey: network_signing_public_key_1.clone(),
            },
        ),
        (
            conf_2.networks[0].peer_id.clone(),
            ConsensusPeerInfo {
                consensus_pubkey: network_signing_public_key_2.clone(),
            },
        ),
    ]
    .into_iter()
    .collect();

    conf_1.consensus.consensus_peers.peers = consensus_peers.clone();
    conf_2.consensus.consensus_peers.peers = consensus_peers;

    // trusted peers
    let trusted_peers: HashMap<_, _> = vec![
        (
            conf_1.networks[0].peer_id.clone(),
            NetworkPeerInfo {
                network_signing_pubkey: network_signing_public_key_1,
                network_identity_pubkey: network_identity_pubkey_key_1,
            },
        ),
        (
            conf_2.networks[0].peer_id.clone(),
            NetworkPeerInfo {
                network_signing_pubkey: network_signing_public_key_2,
                network_identity_pubkey: network_identity_pubkey_key_2,
            },
        ),
    ]
    .into_iter()
    .collect();
    for n in &mut (&mut conf_1).networks {
        n.network_peers.peers = trusted_peers.clone();
    }

    let seed_conf = if conf_1.networks.len() > 0 {
        let peer_id = &mut (&mut conf_1).networks[0].peer_id;
        let mut seed: HashMap<String, Vec<Multiaddr>> = HashMap::new();
        let address_vec = vec!["/memory/1".parse().unwrap()];
        seed.insert(peer_id.clone(), address_vec);
        Some(SeedPeersConfig { seed_peers: seed })
    } else {
        None
    };

    for n in &mut (&mut conf_2).networks {
        n.network_peers.peers = trusted_peers.clone();

        match seed_conf.clone() {
            Some(seed) => {
                n.seed_peers = seed.clone();
            }
            None => {}
        };
    }

    print_ports(&conf_1);
    debug!("conf1:{:?}", conf_1);
    debug!("conf2:{:?}", conf_2);
    let _handle_1 = setup_environment(&mut conf_1, false);

    let runtime_1 = tokio::runtime::Runtime::new().unwrap();
    sleep(Duration::from_secs(20));
    let _handle_2 = setup_environment(&mut conf_2, false);
    let runtime_2 = tokio::runtime::Runtime::new().unwrap();

    print_ports(&conf_2);
    let flag = false;

    let (s1, s2) = if flag {
        let s1 = commit_tx(
            conf_1.admission_control.admission_control_service_port as u32,
            runtime_1.executor(),
        );

        sleep(Duration::from_secs(30));

        let s2 = commit_tx(
            conf_2.admission_control.admission_control_service_port as u32,
            runtime_2.executor(),
        );

        (s1, s2)
    } else {
        let account_keypair_1: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> = create_keypair();
        let account_keypair_2: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> = create_keypair();

        let faucet_1 = faucet_txn(
            AccountAddress::from_public_key(&account_keypair_1.public_key),
            1,
        );
        let faucet_2 = faucet_txn(
            AccountAddress::from_public_key(&account_keypair_2.public_key),
            2,
        );

        let s1 = commit_tx_2(
            conf_1.admission_control.admission_control_service_port as u32,
            runtime_1.executor(),
            &faucet_2,
            (&faucet_1, account_keypair_1),
        );

        sleep(Duration::from_secs(30));

        let s2 = commit_tx_2(
            conf_2.admission_control.admission_control_service_port as u32,
            runtime_2.executor(),
            &faucet_1,
            (&faucet_2, account_keypair_2),
        );

        (s1, s2)
    };

    check_latest_ledger(
        conf_1.admission_control.admission_control_service_port as u32,
        conf_2.admission_control.admission_control_service_port as u32,
        s1,
        s2,
        runtime_1.executor(),
    );

    runtime_1.shutdown_on_idle();
    runtime_2.shutdown_on_idle();
}

fn create_keypair() -> KeyPair<Ed25519PrivateKey, Ed25519PublicKey> {
    let mut seed_rng = rand::rngs::OsRng::new().expect("can't access OsRng");
    let seed_buf: [u8; 32] = seed_rng.gen();
    let mut rng0: StdRng = SeedableRng::from_seed(seed_buf);
    KeyPair::generate_for_testing(&mut rng0)
}

#[test]
fn test_pow_single_node() {
    ::libra_logger::init_for_e2e_testing();
    let mut conf_1 = node_random_conf(true, "/memory/0", 0);
    print_ports(&conf_1);
    debug!("conf1:{:?}", conf_1);
    let _handle_1 = setup_environment(&mut conf_1, false);

    let runtime_1 = tokio::runtime::Runtime::new().unwrap();
    let s = commit_tx(
        conf_1.admission_control.admission_control_service_port as u32,
        runtime_1.executor(),
    );

    check_single_latest_ledger(
        conf_1.admission_control.admission_control_service_port as u32,
        s,
        runtime_1.executor(),
        true,
    );
    runtime_1.shutdown_on_idle();
}

#[test]
fn test_pbft_single_node() {
    ::libra_logger::init_for_e2e_testing();
    let mut config = node_random_conf(false, "/memory/0", 0);
    config.consensus.consensus_type = ConsensusType::PBFT;
    debug!("config : {:?}", config);
    let _handler = libra_node::main_node::setup_environment(&mut config);

    let runtime_1 = tokio::runtime::Runtime::new().unwrap();
    let s = commit_tx(
        config.admission_control.admission_control_service_port as u32,
        runtime_1.executor(),
    );

    check_single_latest_ledger(
        config.admission_control.admission_control_service_port as u32,
        s,
        runtime_1.executor(),
        false,
    );
    runtime_1.shutdown_on_idle();
}

#[test]
fn test_validator_nodes() {
    let (_map_1, consensus_conf_1, _net_conf_1) = ConfigHelpers::gen_validator_nodes(1, None);
    let (_map_2, consensus_conf_2, _net_conf_2) =
        ConfigHelpers::gen_validator_nodes_times(1, Some(TEST_SEED), 1);
    debug!("{:?}", consensus_conf_1);
    debug!("{:?}", consensus_conf_2);
}

#[test]
fn test_rollback_block() {
    ::libra_logger::init_for_e2e_testing();
    let mut conf_1 = node_random_conf(true, "/memory/0", 0);

    let _handle_1 = setup_environment(&mut conf_1, true);

    let runtime_1 = tokio::runtime::Runtime::new().unwrap();
    let s = commit_tx(
        conf_1.admission_control.admission_control_service_port as u32,
        runtime_1.executor(),
    );

    check_single_latest_ledger(
        conf_1.admission_control.admission_control_service_port as u32,
        s,
        runtime_1.executor(),
        true,
    );
    runtime_1.shutdown_on_idle();
}

fn gen_account() -> AccountAddress {
    let mut seed_rng = rand::rngs::OsRng::new().expect("can't access OsRng");
    let seed_buf: [u8; 32] = seed_rng.gen();
    let mut rng0: StdRng = SeedableRng::from_seed(seed_buf);
    let account_keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> =
        KeyPair::generate_for_testing(&mut rng0);

    AccountAddress::from_public_key(&account_keypair.public_key)
}

fn transfer(
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

fn faucet_txn(receiver: AccountAddress, sequence_number: u64) -> SignedTransaction {
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

fn commit_tx_2(
    port: u32,
    executor: TaskExecutor,
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

    let task = Interval::new(Instant::now(), Duration::from_secs(10))
        .take_while(move |_| match shutdown_receiver.try_recv() {
            Err(_) | Ok(Some(_)) => {
                info!("Build block task exit.");
                future::ready(false)
            }
            _ => future::ready(true),
        })
        .for_each(move |_| {
            let account = gen_account();
            let txn = transfer(
                &key_pair.private_key,
                key_pair.public_key.clone(),
                count,
                &account,
            );
            submit_txn_async(client.clone(), faucet_executor.clone(), txn);
            count = count + 1;

            future::ready(())
        });

    executor.spawn(task);

    shutdown_sender
}

fn commit_tx(port: u32, executor: TaskExecutor) -> Sender<()> {
    let (shutdown_sender, mut shutdown_receiver) = channel::<()>();

    let account = gen_account();
    let faucet_executor = executor.clone();
    let task = Interval::new(Instant::now(), Duration::from_secs(10))
        .take_while(move |_| match shutdown_receiver.try_recv() {
            Err(_) | Ok(Some(_)) => {
                info!("Build block task exit.");
                future::ready(false)
            }
            _ => future::ready(true),
        })
        .for_each(move |_| {
            let client = StarChainClient::new("127.0.0.1", port);
            faucet_async(client, faucet_executor.clone(), account, 10);
            future::ready(())
        });

    executor.spawn(task);

    shutdown_sender
}

fn check_latest_ledger(
    port1: u32,
    port2: u32,
    sender_1: Sender<()>,
    sender_2: Sender<()>,
    executor: TaskExecutor,
) {
    let latest_ledger_fut = async move {
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
    };

    executor.spawn(latest_ledger_fut);
}

fn check_single_latest_ledger(
    port: u32,
    sender: Sender<()>,
    executor: TaskExecutor,
    pow_mode: bool,
) {
    let latest_ledger_fut = async move {
        let end_time = Instant::now() + Duration::from_secs(60 * 5);
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
    };

    executor.spawn(latest_ledger_fut);
}
