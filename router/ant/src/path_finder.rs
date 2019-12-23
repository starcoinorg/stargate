// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use futures::lock::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

use sgtypes::message::BalanceQueryResponse;
use sgtypes::s_value::SValue;

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
        if has_key {
            return None;
        }
        let peer = key.get_peer();
        let has_peer = self.seed_hash_map.lock().await.contains_key(&peer);
        if has_peer {
            let mut result = self
                .seed_hash_map
                .lock()
                .await
                .remove(&peer)
                .take()
                .expect("should have key");
            result.append(&mut value);
            return Some(result);
        }
        self.seed_hash_map.lock().await.insert(key, value);
        None
    }
}
