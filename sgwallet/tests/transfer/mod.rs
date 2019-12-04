// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::common::{open_channel, receive_payment, send_payment};
use failure::prelude::*;
use libra_crypto::HashValue;
use sgwallet::wallet::Wallet;
use std::sync::Arc;

pub(crate) async fn transfer_htlc(
    sender_wallet: Arc<Wallet>,
    receiver_wallet: Arc<Wallet>,
) -> Result<()> {
    let fund_amount = 10000;
    open_channel(
        sender_wallet.clone(),
        receiver_wallet.clone(),
        fund_amount,
        fund_amount,
    )
    .await?;
    let preimage = HashValue::random().to_vec();
    let transfer_amount = 1000;
    send_payment(
        sender_wallet.clone(),
        receiver_wallet.clone(),
        transfer_amount,
        HashValue::from_sha3_256(preimage.as_slice()).to_vec(),
        1,
    )
    .await?;
    assert_eq!(
        fund_amount - transfer_amount,
        sender_wallet
            .channel_balance(receiver_wallet.account())
            .await?
    );
    assert_eq!(
        fund_amount,
        receiver_wallet
            .channel_balance(sender_wallet.account())
            .await?
    );
    receive_payment(receiver_wallet.clone(), sender_wallet.clone(), preimage).await?;
    assert_eq!(
        fund_amount - transfer_amount,
        sender_wallet
            .channel_balance(receiver_wallet.account())
            .await?
    );
    assert_eq!(
        fund_amount + transfer_amount,
        receiver_wallet
            .channel_balance(sender_wallet.account())
            .await?
    );
    Ok(())
}
