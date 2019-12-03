// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::channel_transaction::*;
use crate::channel_transaction_sigs::*;
use libra_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    hash::CryptoHash,
    test_utils::KeyPair,
    HashValue, SigningKey, Uniform,
};
use libra_types::channel::Witness;
use libra_types::identifier::Identifier;
use libra_types::language_storage::ModuleId;
use libra_types::transaction::{ChannelTransactionPayloadBodyV2, ScriptAction};
use libra_types::{account_address::AccountAddress, transaction::Script};
use rand::prelude::*;
use std::time::Duration;

//TODO(jole) use Arbitrary
#[test]
fn request_roundtrip_canonical_serialization() {
    let mut rng0: StdRng = SeedableRng::from_seed([0; 32]);
    let keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> =
        KeyPair::generate_for_testing(&mut rng0);
    let sender = AccountAddress::from_public_key(&keypair.public_key);
    let _receiver = AccountAddress::random();
    let _script = Script::new(vec![], vec![]);
    let action = ScriptAction::new_call(
        ModuleId::new(AccountAddress::default(), Identifier::new("M").unwrap()),
        Identifier::new("f").unwrap(),
        vec![],
    );
    let channel_payload = ChannelTransactionPayloadBodyV2::new(
        AccountAddress::random(),
        sender,
        action,
        Witness::default(),
    );
    let signature = keypair
        .private_key
        .sign_message(&CryptoHash::hash(&channel_payload));

    let sequence_number = rng0.next_u64();
    let channel_sequence_number = rng0.next_u64();

    let txn = ChannelTransaction::new(
        rng0.next_u64(),
        AccountAddress::random(),
        channel_sequence_number,
        ChannelOp::Open,
        Vec::new(),
        sender,
        sequence_number,
        Duration::from_secs(rng0.next_u64()),
    );

    let txn_signature = keypair.private_key.sign_message(&CryptoHash::hash(&txn));
    let proposal = ChannelTransactionProposal::new(txn, keypair.public_key.clone(), txn_signature);
    let channel_txn_signatures = ChannelTransactionSigs::new(
        sender,
        keypair.public_key.clone(),
        signature.clone(),
        HashValue::random(),
        signature.clone(),
        None,
    );

    let requests = vec![ChannelTransactionRequest::new(
        proposal,
        channel_txn_signatures,
        false,
    )];
    for request in requests {
        let serialized_bytes = lcs::to_bytes(&request).unwrap();

        let output: ChannelTransactionRequest =
            lcs::from_bytes(serialized_bytes.as_slice()).unwrap();
        assert_eq!(request, output);
    }
}
