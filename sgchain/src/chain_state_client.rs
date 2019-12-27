// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use chain_state::ChainStateRuntime;
use libra_config::config::{NetworkConfig, RoleType};
use network::{
    validator_network::{
        network_builder::{NetworkBuilder, TransportType},
        LibraNetworkProvider, CHAIN_STATE_DIRECT_SEND_PROTOCOL,
    },
    ProtocolId,
};
use parity_multiaddr::Multiaddr;
use std::convert::TryInto;
use tokio::runtime::{Builder, Runtime};

pub fn _setup_chain_state_network_and_environment(
    config: &mut NetworkConfig,
    is_mem: bool,
) -> (
    Runtime,
    Box<dyn LibraNetworkProvider>,
    ChainStateRuntime,
    Multiaddr,
) {
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
        RoleType::Validator,
    );
    network_builder
        .permissioned(false)
        .direct_send_protocols(vec![ProtocolId::from_static(
            CHAIN_STATE_DIRECT_SEND_PROTOCOL,
        )])
        .public(true);

    let seed_peers = config
        .seed_peers
        .seed_peers
        .clone()
        .into_iter()
        .map(|(peer_id, addrs)| (peer_id.try_into().expect("Invalid PeerId"), addrs))
        .collect();
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

    if is_mem {
        network_builder
            .transport(TransportType::PermissionlessMemoryNoise(Some((
                identity_private,
                identity_public,
            ))))
            .connectivity_check_interval_ms(config.connectivity_check_interval_ms)
            .seed_peers(seed_peers)
            .signing_keys((signing_private, signing_public))
            .discovery_interval_ms(config.discovery_interval_ms);
    } else {
        network_builder
            .transport(TransportType::PermissionlessTcpNoise(Some((
                identity_private,
                identity_public,
            ))))
            .connectivity_check_interval_ms(config.connectivity_check_interval_ms)
            .seed_peers(seed_peers)
            .signing_keys((signing_private, signing_public))
            .discovery_interval_ms(config.discovery_interval_ms);
    }

    let (listen_addr, mut network_provider) = network_builder.build();
    //add chain state protocol
    let (chain_state_network_sender, chain_state_network_events) = network_provider
        .add_chain_state(vec![ProtocolId::from_static(
            CHAIN_STATE_DIRECT_SEND_PROTOCOL,
        )]);
    let cs_runtime =
        ChainStateRuntime::bootstrap(chain_state_network_sender, chain_state_network_events);

    (runtime, network_provider, cs_runtime, listen_addr)
}
