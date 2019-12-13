pub use libra_crypto::{
    ed25519::{Ed25519PublicKey, Ed25519Signature},
    hash::CryptoHash,
};

use anyhow::{ensure, Result};
use libra_crypto::ed25519::Ed25519PrivateKey;
use libra_crypto::test_utils::KeyPair;
use libra_crypto::PrivateKey;
use libra_wallet::{
    key_factory::{ChildNumber, KeyFactory, Seed},
    Mnemonic,
};
use std::{
    fs::File,
    io::{BufRead, BufReader},
};

/// Delimiter used to ser/deserialize account data.
pub const DELIMITER: &str = ";";

pub struct WalletLibrary {
    key_factory: KeyFactory,
}

impl WalletLibrary {
    /// Constructor that instantiates a new WalletLibrary from Mnemonic
    pub fn new_from_mnemonic(mnemonic: Mnemonic) -> Self {
        let seed = Seed::new(&mnemonic, "LIBRA");
        WalletLibrary {
            key_factory: KeyFactory::new(&seed).unwrap(),
        }
    }

    /// Recover wallet from input_file_path
    pub fn recover(input_file_path: &str) -> Result<WalletLibrary> {
        let input = File::open(input_file_path)?;
        let mut buffered = BufReader::new(input);

        let mut line = String::new();
        let _ = buffered.read_line(&mut line)?;
        let parts: Vec<&str> = line.split(DELIMITER).collect();
        ensure!(parts.len() == 2, format!("Invalid entry '{}'", line));

        let mnemonic = Mnemonic::from(&parts[0].to_string()[..])?;
        let wallet = WalletLibrary::new_from_mnemonic(mnemonic);

        Ok(wallet)
    }

    pub fn get_keypair(
        &self,
        child_num: u64,
    ) -> Result<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>> {
        let priv_key = self
            .key_factory
            .private_child_raw(ChildNumber::new(child_num))?;
        let pub_key = priv_key.public_key();
        Ok(KeyPair {
            private_key: priv_key,
            public_key: pub_key,
        })
    }
}
