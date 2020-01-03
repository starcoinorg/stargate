// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]
use super::common::{open_channel, receive_payment, send_payment};
use anyhow::Result;
use libra_crypto::HashValue;
use sgwallet::wallet::WalletHandle;
use std::sync::Arc;

pub async fn transfer_htlc(
    sender_wallet: Arc<WalletHandle>,
    receiver_wallet: Arc<WalletHandle>,
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
    let _ = send_payment(
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
    let _ = receive_payment(receiver_wallet.clone(), sender_wallet.clone(), preimage).await?;
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
