// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
use libra_crypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use libra_crypto::HashValue;
use serde::{Deserialize, Serialize};

/// txn signature struct.
/// based on `is_sender_sig` and `is_travel`, the `signature` filed is used to sign different message.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum TxnSignature {
    SenderSig {
        channel_txn_signature: Ed25519Signature,
    },
    ReceiverSig {
        channel_script_body_signature: Ed25519Signature,
    },
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChannelTransactionSigs {
    /// The public key
    pub public_key: Ed25519PublicKey,
    /// tx signature
    pub signature: TxnSignature,
    // hash of output from libra raw tx
    pub write_set_payload_hash: HashValue,
    // signature on write_set_hash
    pub write_set_payload_signature: Ed25519Signature,
}

impl ChannelTransactionSigs {
    pub fn new(
        public_key: Ed25519PublicKey,
        signature: TxnSignature,
        write_set_payload_hash: HashValue,
        write_set_payload_signature: Ed25519Signature,
    ) -> Self {
        Self {
            public_key,
            signature,
            write_set_payload_hash,
            write_set_payload_signature,
        }
    }
}
