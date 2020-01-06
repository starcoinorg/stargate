// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::get_unix_ts;
use anyhow::{Error, Result};
use futures::lock::Mutex;
use hex;
use libra_crypto::HashValue;
use libra_logger::prelude::*;
use libra_types::account_address::{AccountAddress, ADDRESS_LENGTH};
use rand::prelude::*;
use std::collections::HashMap;
use std::convert::{From, TryFrom};
use std::sync::Arc;

#[derive(Clone)]
pub struct InvoiceManager {
    r_hash_map: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
    r_hash_previous_hop_map: Arc<Mutex<HashMap<Vec<u8>, AccountAddress>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invoice {
    pub r_hash: Vec<u8>,
    pub amount: u64,
    pub receiver: AccountAddress,
}

impl Invoice {
    fn as_vec(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.receiver.to_vec());
        result.extend_from_slice(&self.amount.to_be_bytes());
        result.extend_from_slice(&self.r_hash);
        result
    }
}

impl TryFrom<Vec<u8>> for Invoice {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        let receiver = AccountAddress::try_from(&value[0..ADDRESS_LENGTH])?;
        let mut amount_bytes: [u8; 8] = [0; 8];
        amount_bytes.copy_from_slice(&value[ADDRESS_LENGTH..ADDRESS_LENGTH + 8]);
        let amount = u64::from_be_bytes(amount_bytes);
        let r_hash = Vec::from(&value[ADDRESS_LENGTH + 8..]);
        Ok(Self {
            receiver,
            amount,
            r_hash,
        })
    }
}

impl From<Invoice> for Vec<u8> {
    fn from(value: Invoice) -> Self {
        value.as_vec()
    }
}

impl TryFrom<String> for Invoice {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        let bytes_value = hex::decode(value)?;
        Invoice::try_from(bytes_value)
    }
}

impl From<Invoice> for String {
    fn from(value: Invoice) -> Self {
        hex::encode_upper(&value.as_vec())
    }
}

impl InvoiceManager {
    pub fn new() -> Self {
        Self {
            r_hash_map: Arc::new(Mutex::new(HashMap::new())),
            r_hash_previous_hop_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn new_invoice(&self, amount: u64, receiver: AccountAddress) -> Invoice {
        let mut rng: StdRng = SeedableRng::seed_from_u64(get_unix_ts());
        let preimage = HashValue::random_with_rng(&mut rng).to_vec();
        let r_hash = HashValue::from_sha3_256(preimage.as_slice()).to_vec();

        info!(
            "preimage is {},r_hash is {}",
            hex::encode(preimage.clone()),
            hex::encode(r_hash.clone())
        );
        self.r_hash_map
            .lock()
            .await
            .insert(r_hash.clone(), preimage.clone());
        Invoice {
            r_hash,
            amount,
            receiver,
        }
    }

    pub async fn get_preimage(&self, r_hash: &HashValue) -> Option<Vec<u8>> {
        match self.r_hash_map.lock().await.get(&r_hash.to_vec()) {
            Some(v) => {
                let mut result = Vec::new();
                result.extend_from_slice(v);
                return Some(result);
            }
            None => {
                return None;
            }
        };
    }

    pub async fn add_previous_hop(&self, r_hash: HashValue, previous_addr: AccountAddress) {
        self.r_hash_previous_hop_map
            .lock()
            .await
            .insert(r_hash.to_vec(), previous_addr);
    }

    pub async fn get_previous_hop(&self, preimage: Vec<u8>) -> Option<AccountAddress> {
        let r_hash = HashValue::from_sha3_256(preimage.as_slice()).to_vec();

        match self
            .r_hash_previous_hop_map
            .lock()
            .await
            .get(&r_hash.to_vec())
        {
            Some(v) => {
                return Some(v.clone());
            }
            None => {
                return None;
            }
        };
    }
}

#[test]
fn test_invoice() {
    use std::convert::TryInto;

    let preimage = HashValue::random().to_vec();
    let r_hash = HashValue::from_sha3_256(preimage.as_slice()).to_vec();
    let account_address = AccountAddress::random();
    let amount = 1000;

    let invoice = Invoice {
        r_hash,
        amount,
        receiver: account_address,
    };

    let invoice_string: String = invoice.clone().into();
    let invoice_decode: Invoice = invoice_string.try_into().unwrap();

    assert_eq!(invoice_decode.receiver, invoice.receiver);
    assert_eq!(invoice_decode.r_hash, invoice.r_hash);
    assert_eq!(invoice_decode.amount, invoice.amount);
}
