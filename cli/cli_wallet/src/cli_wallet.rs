use crate::{
    error::*,
    //io_utils,
    key_factory::{ChildNumber, KeyFactory, Seed},
    mnemonic::Mnemonic,
};
use libra_crypto::hash::CryptoHash;
use proto_conv::{FromProto, IntoProto};
use protobuf::Message;
use rand::{rngs::EntropyRng, Rng};
use std::{collections::HashMap, path::Path};
use types::{
    account_address::AccountAddress,
    proto::transaction::SignedTransaction as ProtoSignedTransaction,
    transaction::{RawTransaction, RawTransactionBytes, SignedTransaction},
    transaction_helpers::TransactionSigner,
};
use nextgen_crypto::traits::Uniform;
use nextgen_crypto::test_utils::KeyPair;
use std::time::{SystemTime,UNIX_EPOCH};
use rand::prelude::*;
use nextgen_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use nextgen_crypto::traits::SigningKey;


pub struct WalletLibrary {
    addr:Option<AccountAddress>,
}

impl WalletLibrary{

    pub fn new()->Self{
        Self{
            addr:None,
        }
    }

    pub fn get_address(&mut self) -> AccountAddress {
        match self.addr {
            Some(addr) => {
                return addr;
            },
            None => {
                let mut rng: StdRng = SeedableRng::seed_from_u64(get_unix_ts());//SeedableRng::from_seed([0; 32]);
                let keypair:KeyPair<Ed25519PrivateKey,Ed25519PublicKey> = KeyPair::generate_for_testing(&mut rng);
                let account_address = AccountAddress::from_public_key(&keypair.public_key);         
                self.addr = Some(account_address);
                return  account_address  ;
            },
        }        
    }
}

fn get_unix_ts()->u64{
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");;   
    since_the_epoch.as_millis() as u64
}