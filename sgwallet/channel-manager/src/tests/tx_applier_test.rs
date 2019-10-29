// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::tx_applier::TxApplier;
use crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use crypto::test_utils::KeyPair;
use crypto::{HashValue, Uniform};
use libra_types::access_path::AccessPath;

use libra_types::transaction::{ChannelScriptBody, Script};
use libra_types::transaction_helpers::ChannelPayloadSigner;
use libra_types::vm_error::StatusCode;
use libra_types::write_set::{WriteOp, WriteSet, WriteSetMut};
use rand::prelude::*;
use sgstorage::channel_db::ChannelAddressProvider;
use sgstorage::generate_random_channel_store;
use sgtypes::channel_transaction::{ChannelOp, ChannelTransaction};
use sgtypes::channel_transaction_sigs::{ChannelTransactionSigs, TxnSignature};
use sgtypes::channel_transaction_to_commit::ChannelTransactionToApply;
use sgtypes::signed_channel_transaction::SignedChannelTransaction;
use std::time::Duration;

#[test]
fn test_tx_applier() {
    logger::try_init_for_testing();
    let store = generate_random_channel_store();
    let mut tx_applier = TxApplier::new(store.clone());

    let mut rng0: StdRng = SeedableRng::from_seed([0; 32]);

    let keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey> =
        KeyPair::generate_for_testing(&mut rng0);
    let sender = store.db().owner_address();
    let receiver = store.db().participant_address();
    let script = Script::new(vec![], vec![]);
    let channel_script_payload = ChannelScriptBody::new(0, WriteSet::default(), receiver, script);
    let signature = keypair
        .sign_script_payload(&channel_script_payload)
        .unwrap();
    let sequence_number = rng0.next_u64();
    let _channel_sequence_number = rng0.next_u64();

    let txn = ChannelTransaction::new(
        rng0.next_u64(),
        ChannelOp::Open,
        sender,
        sequence_number,
        receiver,
        0,
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
    let apply_result = tx_applier.apply(txn_to_apply);
    assert!(
        apply_result.is_ok(),
        format!("err: {:?}", apply_result.unwrap_err())
    );
    let ws = store.get_latest_write_set();
    assert!(ws.is_some());
    assert!(ws.unwrap().len() > 0);
}
