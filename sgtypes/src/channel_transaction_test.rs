// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::channel_transaction::*;
use crate::channel_transaction_sigs::*;
use libra_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    hash::CryptoHash,
    test_utils::KeyPair,
    HashValue, Uniform,
};
use libra_types::{
    account_address::AccountAddress,
    transaction::{helpers::ChannelPayloadSigner, ChannelScriptBody, ChannelWriteSetBody, Script},
    write_set::WriteSet,
};
use rand::prelude::*;
use std::time::Duration;

//TODO(jole) use Arbitrary
#[test]
fn request_roundtrip_canonical_serialization() {
    let mut rng0: StdRng = SeedableRng::from_seed([0; 32]);
    let keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> =
        KeyPair::generate_for_testing(&mut rng0);
    let sender = AccountAddress::from_public_key(&keypair.public_key);
    let receiver = AccountAddress::random();
    let script = Script::new(vec![], vec![]);
    let channel_script_payload = ChannelScriptBody::new(0, WriteSet::default(), receiver, script);
    let signature = keypair
        .sign_script_payload(&channel_script_payload)
        .unwrap();
    let sequence_number = rng0.next_u64();
    let channel_sequence_number = rng0.next_u64();

    let requests = vec![
        ChannelTransactionRequest::new(
            ChannelTransaction::new(
                rng0.next_u64(),
                ChannelOp::Open,
                sender,
                sequence_number,
                receiver,
                channel_sequence_number,
                Duration::from_secs(rng0.next_u64()),
                Vec::new(),
            ),
            ChannelTransactionSigs::new(
                keypair.public_key.clone(),
                TxnSignature::SenderSig {
                    channel_txn_signature: signature.clone(),
                },
                ChannelWriteSetBody::new(channel_sequence_number, WriteSet::default(), receiver)
                    .hash(),
                signature.clone(),
            ),
            true,
        ),
        ChannelTransactionRequest::new(
            ChannelTransaction::new(
                rng0.next_u64(),
                ChannelOp::Execute {
                    package_name: "Test".to_string(),
                    script_name: "Test".to_string(),
                },
                sender,
                sequence_number,
                receiver,
                channel_sequence_number,
                Duration::from_secs(rng0.next_u64()),
                Vec::new(),
            ),
            ChannelTransactionSigs::new(
                keypair.public_key.clone(),
                TxnSignature::ReceiverSig {
                    channel_script_body_signature: signature.clone(),
                },
                HashValue::default(),
                signature.clone(),
            ),
            false,
        ),
    ];
    for request in requests {
        let serialized_bytes = lcs::to_bytes(&request).unwrap();

        let output: ChannelTransactionRequest =
            lcs::from_bytes(serialized_bytes.as_slice()).unwrap();
        assert_eq!(request, output);
    }
}
