use crate::chain_state_client::_setup_chain_state_network_and_environment;
use crate::star_chain_client::gen_node_config_with_genesis;
use crate::tests::setup_environment;
use libra_logger::prelude::*;
use std::thread::sleep;
use std::time::Duration;

#[test]
fn test_chain_state() {
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

    debug!("conf1:{:?}", conf_1);
    debug!("conf2:{:?}", conf_2);
    let handle_1 = setup_environment(&mut conf_1, false);

    sleep(Duration::from_secs(20));
    let (runtime_2, network_provider_2, cs_runtime, _multi_address) =
        _setup_chain_state_network_and_environment(
            conf_2
                .validator_network
                .as_mut()
                .expect("validator_network is none."),
            true,
        );
    runtime_2.handle().clone().spawn(network_provider_2.start());

    sleep(Duration::from_secs(1 * 60));
    drop(handle_1);
    drop(cs_runtime);
    drop(runtime_2);
    sleep(Duration::from_secs(5));
}
