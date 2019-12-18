// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use futures::channel::{mpsc, oneshot};
use libra_logger::prelude::*;

#[derive(Debug)]
pub enum Msg<ReqT, RespT> {
    Call {
        msg: ReqT,
        tx: oneshot::Sender<RespT>,
    },
    Cast {
        msg: ReqT,
    },
}

pub async fn call<ReqT, RespT>(
    mut mailbox_sender: mpsc::Sender<Msg<ReqT, RespT>>,
    request: ReqT,
) -> Result<RespT> {
    let (tx, rx) = oneshot::channel();
    if let Err(_e) = mailbox_sender.try_send(Msg::Call { msg: request, tx }) {
        bail!("mailbox is full or close");
    }
    match rx.await {
        Ok(result) => Ok(result),
        Err(_) => bail!("sender dropped"),
    }
}

pub fn cast<ReqT, RespT>(
    mut mailbox_sender: mpsc::Sender<Msg<ReqT, RespT>>,
    request: ReqT,
) -> Result<()> {
    if let Err(e) = mailbox_sender.try_send(Msg::Cast { msg: request }) {
        if e.is_full() {
            bail!("mailbox is full");
        } else {
            error!("mailbox is closed");
        }
    }
    Ok(())
}

pub fn respond_with<T>(responder: oneshot::Sender<T>, msg: T) {
    if let Err(_t) = responder.send(msg) {
        error!("fail to send back response, receiver is dropped",);
    };
}
