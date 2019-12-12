// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use failure::prelude::*;
use futures::lock::Mutex;
use hex;
use libra_crypto::HashValue;
use libra_logger::prelude::*;
use libra_types::account_address::{AccountAddress, ADDRESS_LENGTH};
use std::collections::HashMap;
use std::convert::{From, TryFrom};
use std::sync::Arc;

#[derive(Clone)]
pub struct InvoiceManager {
    r_hash_map: Arc<Mutex<HashMap<Vec<u8>, (Vec<u8>)>>>,
    r_hash_previous_hop_map: Arc<Mutex<HashMap<Vec<u8>, AccountAddress>>>,
}

#[derive(Clone, Debug)]
pub struct Invoice {
    pub r_hash: Vec<u8>,
    pub receiver: AccountAddress,
}

impl Invoice {
    fn as_vec(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.receiver.to_vec());
        result.extend_from_slice(&self.r_hash);
        result
    }
}

impl TryFrom<Vec<u8>> for Invoice {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        let receiver = AccountAddress::try_from(&value[0..ADDRESS_LENGTH])?;
        let r_hash = Vec::from(&value[ADDRESS_LENGTH..]);
        Ok(Self { receiver, r_hash })
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

    pub async fn new_invoice(&self, receiver: AccountAddress) -> Invoice {
        let preimage = HashValue::random().to_vec();
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
        Invoice { r_hash, receiver }
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
