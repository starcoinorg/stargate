// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use libra_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    hash::CryptoHash,
    test_utils::KeyPair,
    HashValue, SigningKey, Uniform,
};
use libra_types::{
    access_path::AccessPath,
    account_address::AccountAddress,
    vm_error::StatusCode,
    write_set::{WriteOp, WriteSetMut},
};
use rand::prelude::*;
use sgtypes::{
    applied_channel_txn::AppliedChannelTxn,
    channel_transaction::{ChannelOp, ChannelTransaction, ChannelTransactionProposal},
    channel_transaction_sigs::ChannelTransactionSigs,
    channel_transaction_to_commit::ChannelTransactionToCommit,
    signed_channel_transaction::SignedChannelTransaction,
};
use std::{collections::BTreeMap, time::Duration};

fn generate_txn_to_apply(
    sender: AccountAddress,
    _receiver: AccountAddress,
    channel_sequence_number: u64,
) -> ChannelTransactionToCommit {
    let mut rng0: StdRng = SeedableRng::from_seed([0; 32]);

    let keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> =
        KeyPair::generate_for_testing(&mut rng0);
    let channel_address = AccountAddress::random();
    let signature = keypair.private_key.sign_message(&HashValue::random());

    let txn = ChannelTransaction::new(
        rng0.next_u64(),
        channel_address,
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
    let txn_to_apply = ChannelTransactionToCommit {
        signed_channel_txn: AppliedChannelTxn::Offchain(SignedChannelTransaction {
            raw_tx: txn,
            signatures,
        }),
        write_set: ws,
        events: vec![],
        major_status: StatusCode::ABORTED,
        gas_used: 0,
    };

    txn_to_apply
}

mod channel_test;
mod tx_applier_test;
