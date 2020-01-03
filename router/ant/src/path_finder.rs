// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use futures::lock::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

use sgtypes::message::{AntFinalMessage, BalanceQueryResponse};
use sgtypes::s_value::SValue;

use anyhow::Result;
use libra_crypto::HashValue;
use libra_logger::prelude::*;

#[derive(Clone)]
pub struct SeedManager {
    seed_hash_map: Arc<Mutex<HashMap<SValue, Vec<BalanceQueryResponse>>>>,
}

impl SeedManager {
    pub fn new() -> Self {
        Self {
            seed_hash_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn match_or_add(
        &self,
        key: SValue,
        mut value: Vec<BalanceQueryResponse>,
    ) -> Option<Vec<BalanceQueryResponse>> {
        let has_key = self.seed_hash_map.lock().await.contains_key(&key);
        info!("has key is {}", has_key);
        if has_key {
            return None;
        }
        let peer = key.get_peer();
        let has_peer = self.seed_hash_map.lock().await.contains_key(&peer);
        info!("peer is is {},has peer is {}", peer, has_peer);
        if has_peer {
            let mut result = self
                .seed_hash_map
                .lock()
                .await
                .remove(&peer)
                .take()
                .expect("should have key");
            result.append(&mut value);
            info!("return result {:?}", result);
            return Some(result);
        }
        info!("insert key {},value {:?}", key, value);
        self.seed_hash_map.lock().await.insert(key, value);
        None
    }
}

pub struct PathStore {
    seed_hash_map: Mutex<HashMap<HashValue, Vec<AntFinalMessage>>>,
}

impl PathStore {
    pub fn new() -> Self {
        Self {
            seed_hash_map: Mutex::new(HashMap::new()),
        }
    }

    pub async fn add_path(&self, r: HashValue, path: AntFinalMessage) -> Result<()> {
        let has_key = self.seed_hash_map.lock().await.contains_key(&r);

        if !has_key {
            let mut path_set = Vec::new();
            path_set.push(path);
            self.seed_hash_map.lock().await.insert(r, path_set);
        } else {
            let mut vec = self
                .seed_hash_map
                .lock()
                .await
                .remove(&r)
                .expect("should have");
            vec.push(path);
            self.seed_hash_map.lock().await.insert(r, vec);
        }

        Ok(())
    }

    pub async fn take_path(&self, r: &HashValue) -> Option<Vec<AntFinalMessage>> {
        self.seed_hash_map.lock().await.remove(&r)
    }
}
