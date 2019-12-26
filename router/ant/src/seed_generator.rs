use rand::prelude::*;

use libra_crypto::{
    hash::{CryptoHasher, TestOnlyHasher},
    HashValue,
};

use sgtypes::s_value::SValue;

use std::time::{SystemTime, UNIX_EPOCH};

fn get_unix_ts() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_millis() as u64
}

pub fn generate_random_u128() -> u128 {
    let mut rng: StdRng = SeedableRng::seed_from_u64(get_unix_ts());

    rng.gen::<u128>()
}

pub struct SValueGenerator {
    sender_r: u128,
    receiver_r: u128,
}

impl SValueGenerator {
    pub fn new(sender_r: u128, receiver_r: u128) -> Self {
        Self {
            sender_r,
            receiver_r,
        }
    }

    pub fn get_r(&self) -> HashValue {
        let mut bytes_vec = Vec::new();
        bytes_vec.extend_from_slice(&self.sender_r.to_le_bytes());
        bytes_vec.extend_from_slice(&self.receiver_r.to_le_bytes());

        let mut hasher = TestOnlyHasher::default();
        hasher.write(bytes_vec.as_slice());
        hasher.finish()
    }

    pub fn get_s(&self, is_sender: bool) -> SValue {
        let mut bytes_vec = Vec::new();
        bytes_vec.extend_from_slice(&self.sender_r.to_le_bytes());
        bytes_vec.extend_from_slice(&self.receiver_r.to_le_bytes());

        let mut result: [u8; 33] = [0; 33];
        if !is_sender {
            result[0] = 1;
        }
        result[1..33].copy_from_slice(&bytes_vec);
        SValue::new(result)
    }
}
