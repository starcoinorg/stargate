use crate::star_chain_client::gen_node_config_with_genesis;
use anyhow::{ensure, Result};
use libra_config::config::{NetworkConfig, TestConfig};
use libra_crypto::ed25519::Ed25519PrivateKey;
use libra_crypto::traits::Uniform;
use libra_crypto::x25519::X25519StaticPrivateKey;
use libra_logger::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

#[test]
fn test_config_times() {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut test_conf_1 = TestConfig::new_with_temp_dir();
    test_conf_1.random(&mut rng);

    let mut test_conf_2 = TestConfig::new_with_temp_dir();
    test_conf_2.random(&mut rng);

    info!("test_conf_1 : {:?}", test_conf_1);
    info!("test_conf_2 : {:?}", test_conf_2);
}

#[test]
fn test_network_conf() {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut network_conf_1 = NetworkConfig::default();
    network_conf_1.random(&mut rng);
    let mut network_conf_2 = NetworkConfig::default();
    network_conf_2.random(&mut rng);
    info!("network_conf_1 : {:?}", network_conf_1);
    info!("network_conf_2 : {:?}", network_conf_2);
}

#[test]
fn test_validator_conf() {
    let conf_1 = gen_node_config_with_genesis(1, true, true, Some("/memory/0"), false);
    let conf_2 = gen_node_config_with_genesis(2, true, true, Some("/memory/0"), false);
    info!("conf_1 : {:?}", conf_1);
    info!("conf_2 : {:?}", conf_2);
}

#[test]
fn test_keys() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let signing_key_1 = Ed25519PrivateKey::generate_for_testing(&mut rng);
    let identity_key_1 = X25519StaticPrivateKey::generate_for_testing(&mut rng);

    let signing_key_2 = Ed25519PrivateKey::generate_for_testing(&mut rng);
    let identity_key_2 = X25519StaticPrivateKey::generate_for_testing(&mut rng);

    ensure!((signing_key_1 != signing_key_2), "signing_key");
    ensure!((identity_key_1 != identity_key_2), "identity_key");

    Ok(())
}

fn keys(times: usize) -> (Ed25519PrivateKey, X25519StaticPrivateKey) {
    let mut rng = StdRng::from_seed([0u8; 32]);
    if times > 0 {
        for _ in 0..times {
            let _ = Ed25519PrivateKey::generate_for_testing(&mut rng);
        }
    }
    let signing_key = Ed25519PrivateKey::generate_for_testing(&mut rng);

    if times > 0 {
        for _ in 0..times {
            let _ = X25519StaticPrivateKey::generate_for_testing(&mut rng);
        }
    }
    let identity_key = X25519StaticPrivateKey::generate_for_testing(&mut rng);
    (signing_key, identity_key)
}

#[test]
fn test_keys_2() -> Result<()> {
    let (signing_key_1, identity_key_1) = keys(0);

    let (signing_key_2, identity_key_2) = keys(0);

    ensure!((signing_key_1 == signing_key_2), "signing_key");
    ensure!((identity_key_1 == identity_key_2), "identity_key");

    Ok(())
}

#[test]
fn test_keys_3() -> Result<()> {
    let (signing_key_1, identity_key_1) = keys(0);

    let (signing_key_2, identity_key_2) = keys(1);

    ensure!((signing_key_1 != signing_key_2), "signing_key");
    ensure!((identity_key_1 != identity_key_2), "identity_key");

    Ok(())
}

#[test]
fn test_genesis() {
    let conf = gen_node_config_with_genesis(1, false, true, Some("/memory/0"), false);
    info!("{:?}", conf);
}
