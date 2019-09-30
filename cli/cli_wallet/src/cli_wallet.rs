use crate::{
    error::*,
    key_factory::{ChildNumber, KeyFactory, Seed},
    mnemonic::Mnemonic,
};
use libra_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature},
    hash::CryptoHash,
    test_utils::KeyPair,
    traits::{SigningKey, Uniform},
};
use proto_conv::{FromProto, IntoProto};
use protobuf::Message;
use rand::{prelude::*, rngs::EntropyRng, Rng};
use serde;
use std::{
    collections::HashMap,
    convert::TryFrom,
    fs,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use types::{
    account_address::AccountAddress,
    proto::transaction::SignedTransaction as ProtoSignedTransaction,
    transaction::{RawTransaction, SignedTransaction},
    transaction_helpers::TransactionSigner,
};

pub struct WalletLibrary {
    addr: Option<AccountAddress>,
    key_pair: Option<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
}

fn path_exists(path: &str) -> bool {
    fs::metadata(path).is_ok()
}

impl WalletLibrary {
    pub fn new(faucet_account_file: &str) -> Self {
        let mut result = Self {
            addr: None,
            key_pair: None,
        };
        if (path_exists(faucet_account_file)) {
            result.load_from_file(faucet_account_file);
        } else {
            result.gen_new_address();
            let private_data = result
                .key_pair
                .clone()
                .expect("no key")
                .private_key
                .to_bytes();
            let public_data = result
                .key_pair
                .clone()
                .expect("no key")
                .public_key
                .to_bytes();
            let mut content = vec![];
            content.extend_from_slice(&private_data[..]);
            content.extend_from_slice(&public_data[..]);
            fs::write(faucet_account_file, content).unwrap();
        }

        result
    }

    fn load_from_file(&mut self, faucet_account_file: &str) {
        match fs::read(faucet_account_file) {
            Ok(data) => {
                //let keypair:KeyPair<Ed25519PrivateKey,Ed25519PublicKey>=bincode::deserialize(&
                // data[..]).expect("Unable to deserialize faucet account file");
                let private_key = Ed25519PrivateKey::try_from(&data[0..32]).unwrap();
                let public_key = Ed25519PublicKey::try_from(&data[32..]).unwrap();
                let keypair = KeyPair {
                    private_key,
                    public_key,
                };
                let account_address = AccountAddress::from_public_key(&keypair.public_key);

                self.addr = Some(account_address);
                self.key_pair = Some(keypair);
            }
            Err(e) => {
                panic!(
                    "Unable to read faucet account file: {}, {}",
                    faucet_account_file, e
                );
            }
        }
    }

    pub fn get_address(&mut self) -> AccountAddress {
        match self.addr {
            Some(addr) => {
                return addr;
            }
            None => {
                return self.gen_new_address();
            }
        }
    }

    pub fn gen_new_address(&mut self) -> AccountAddress {
        let mut rng: StdRng = SeedableRng::seed_from_u64(get_unix_ts()); //SeedableRng::from_seed([0; 32]);
        let keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> =
            KeyPair::generate_for_testing(&mut rng);
        let account_address = AccountAddress::from_public_key(&keypair.public_key);
        self.addr = Some(account_address);
        self.key_pair = Some(keypair);
        account_address
    }

    pub fn sign_txn(&self, txn: RawTransaction) -> Result<SignedTransaction> {
        match self.addr {
            None => Err(WalletError::LibraWalletGeneric(
                "Well, that address is nowhere to be found... This is awkward".to_string(),
            )),
            Some(addr) => {
                if (addr == txn.sender()) {
                    let child_key = self.key_pair.as_ref().expect("should have keypair");
                    match txn.sign(&child_key.private_key, child_key.public_key.clone()) {
                        Ok(signed_txn) => Ok(signed_txn.into_inner()),
                        Err(e) => Err(WalletError::LibraWalletGeneric(format!("err is {}", e))),
                    }
                } else {
                    Err(WalletError::LibraWalletGeneric(
                        "Well, that address is nowhere to be found... This is awkward".to_string(),
                    ))
                }
            }
        }
    }
}

fn get_unix_ts() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");;  
    since_the_epoch.as_millis() as u64
}

impl TransactionSigner for WalletLibrary {
    fn sign_txn(&self, raw_txn: RawTransaction) -> failure::prelude::Result<SignedTransaction> {
        Ok(self.sign_txn(raw_txn)?)
    }
}
