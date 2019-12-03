use rand::Rng;

use libra_crypto::{
    hash::{CryptoHasher, TestOnlyHasher},
    HashValue,
};

use sgtypes::s_value::SValue;

pub fn generate() -> u128 {
    let mut rng = rand::thread_rng();

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

    pub fn get_r(self) -> HashValue {
        let mut bytes_vec = Vec::new();
        bytes_vec.copy_from_slice(&self.sender_r.to_le_bytes());
        bytes_vec.copy_from_slice(&self.receiver_r.to_le_bytes());

        let mut hasher = TestOnlyHasher::default();
        hasher.write(bytes_vec.as_slice());
        hasher.finish()
    }

    pub fn get_s(self, is_sender: bool) -> SValue {
        let mut result: [u8; 33] = [0; 33];
        if !is_sender {
            result[0] = 1;
        }
        result[1..33].copy_from_slice(self.get_r().as_ref());
        SValue::new(result)
    }
}
