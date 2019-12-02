// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use libra_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use libra_crypto::hash::CryptoHash;
use libra_crypto::test_utils::KeyPair;
use libra_crypto::{HashValue, SigningKey, Uniform};
use libra_types::access_path::AccessPath;
use libra_types::account_address::AccountAddress;
use libra_types::transaction::{helpers::ChannelPayloadSigner, ChannelScriptBody, Script};
use libra_types::vm_error::StatusCode;
use libra_types::write_set::{WriteOp, WriteSet, WriteSetMut};
use rand::prelude::*;
use sgtypes::channel_transaction::{ChannelOp, ChannelTransaction, ChannelTransactionProposal};
use sgtypes::channel_transaction_sigs::ChannelTransactionSigs;
use sgtypes::channel_transaction_to_commit::ChannelTransactionToApply;
use sgtypes::signed_channel_transaction::SignedChannelTransaction;
use std::collections::BTreeMap;
use std::time::Duration;

fn generate_txn_to_apply(
    sender: AccountAddress,
    receiver: AccountAddress,
    channel_sequence_number: u64,
) -> ChannelTransactionToApply {
    let mut rng0: StdRng = SeedableRng::from_seed([0; 32]);

    let keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> =
        KeyPair::generate_for_testing(&mut rng0);

    let script = Script::new(vec![], vec![]);
    let channel_script_payload = ChannelScriptBody::new(0, WriteSet::default(), receiver, script);

    let signature = keypair
        .sign_script_payload(&channel_script_payload)
        .unwrap();

    let txn = ChannelTransaction::new(
        rng0.next_u64(),
        AccountAddress::random(),
        channel_sequence_number,
        ChannelOp::Open,
        Vec::new(),
        sender,
        rng0.next_u64(),
        Duration::from_secs(rng0.next_u64()),
    );
    let txn_signature = keypair.private_key.sign_message(&CryptoHash::hash(&txn));
    let _proposal =
        ChannelTransactionProposal::new(txn.clone(), keypair.public_key.clone(), txn_signature);
    let channel_txn_signatures = ChannelTransactionSigs::new(
        sender,
        keypair.public_key.clone(),
        signature.clone(),
        HashValue::random(),
        signature.clone(),
        None,
    );
    let ws = WriteSetMut::new(vec![(
        AccessPath::new(sender, vec![0, 0, 0]),
        WriteOp::Deletion,
    )])
    .freeze()
    .unwrap();

    let signatures = {
        let mut s = BTreeMap::new();
        s.insert(channel_txn_signatures.address, channel_txn_signatures);
        s
    };
    let txn_to_apply = ChannelTransactionToApply {
        signed_channel_txn: SignedChannelTransaction {
            raw_tx: txn,
            signatures,
        },
        write_set: Some(ws),
        events: vec![],
        travel: false,
        major_status: StatusCode::ABORTED,
        gas_used: 0,
    };

    txn_to_apply
}

mod channel_test;
mod tx_applier_test;
