// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use crypto::test_utils::KeyPair;
use crypto::{HashValue, Uniform};
use libra_types::access_path::AccessPath;
use libra_types::account_address::AccountAddress;
use libra_types::transaction::{ChannelScriptBody, Script};
use libra_types::transaction_helpers::ChannelPayloadSigner;
use libra_types::vm_error::StatusCode;
use libra_types::write_set::{WriteOp, WriteSet, WriteSetMut};
use rand::prelude::*;
use sgtypes::channel_transaction::{ChannelOp, ChannelTransaction};
use sgtypes::channel_transaction_sigs::{ChannelTransactionSigs, TxnSignature};
use sgtypes::channel_transaction_to_commit::ChannelTransactionToApply;
use sgtypes::signed_channel_transaction::SignedChannelTransaction;
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
        ChannelOp::Open,
        sender,
        rng0.next_u64(),
        receiver,
        channel_sequence_number,
        Duration::from_secs(rng0.next_u64()),
        Vec::new(),
    );
    let ws = WriteSetMut::new(vec![(
        AccessPath::new(sender, vec![0, 0, 0]),
        WriteOp::Deletion,
    )])
    .freeze()
    .unwrap();

    let txn_to_apply = ChannelTransactionToApply {
        signed_channel_txn: SignedChannelTransaction {
            raw_tx: txn,
            sender_signature: ChannelTransactionSigs::new(
                keypair.public_key.clone(),
                TxnSignature::SenderSig {
                    channel_txn_signature: signature.clone(),
                },
                HashValue::default(),
                signature.clone(),
            ),
            receiver_signature: ChannelTransactionSigs::new(
                keypair.public_key.clone(),
                TxnSignature::ReceiverSig {
                    channel_script_body_signature: signature.clone(),
                },
                HashValue::default(),
                signature.clone(),
            ),
        },
        write_set: ws,
        travel: false,
        events: vec![],
        major_status: StatusCode::ABORTED,
    };

    txn_to_apply
}

mod channel_manager_test;
mod channel_test;
mod tx_applier_test;
