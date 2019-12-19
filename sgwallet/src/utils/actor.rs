// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use async_trait::async_trait;
use futures::channel::{mpsc, oneshot};
use futures::{FutureExt, StreamExt};
use libra_logger::prelude::*;
use std::marker::PhantomData;
use std::sync::Arc;
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

#[derive(Debug, Clone)]
pub struct ActorHandle<S, M> {
    inner: S,
    mail_sender: mpsc::Sender<M>,
    shutdown_tx: Arc<oneshot::Sender<()>>,
}

impl<S, ReqT, RespT> ActorHandle<S, Msg<ReqT, RespT>> {
    pub fn new(
        s: S,
        sender: mpsc::Sender<Msg<ReqT, RespT>>,
        shutdown_tx: Arc<oneshot::Sender<()>>,
    ) -> Self {
        Self {
            inner: s,
            mail_sender: sender,
            shutdown_tx,
        }
    }

    pub async fn call(&self, req: ReqT) -> Result<RespT> {
        call(self.mail_sender.clone(), req).await
    }
    pub fn cast(&self, msg: ReqT) -> Result<()> {
        cast(self.mail_sender.clone(), msg)
    }
}

#[async_trait]
pub trait TypedActor<ReqT, RespT>: Send {
    async fn handle_call(&mut self, req: ReqT) -> RespT;
    async fn handle_cast(&mut self, msg: ReqT);
}

/// `S` is inner state of actor, and `HS` is inner state of actor handle
pub struct Actor<S, H> {
    inner: S,
    phantom_data: PhantomData<H>,
}

impl<S, H> Actor<S, H> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            phantom_data: PhantomData,
        }
    }
}

impl<S, HS, ReqT, RespT> Actor<S, (HS, ReqT, RespT)>
where
    HS: Send + 'static,
    ReqT: Send + 'static,
    RespT: Send + 'static,
    S: TypedActor<ReqT, RespT> + 'static,
{
    pub fn start(
        self,
        executor: tokio::runtime::Handle,
        hs: HS,
    ) -> ActorHandle<HS, Msg<ReqT, RespT>> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (tx, rx) = mpsc::channel(1024);
        executor.spawn(self.inner_start(rx, shutdown_rx));
        ActorHandle::new(hs, tx, Arc::new(shutdown_tx))
    }
    async fn inner_start(
        mut self,
        mailbox: mpsc::Receiver<Msg<ReqT, RespT>>,
        shutdown: oneshot::Receiver<()>,
    ) {
        let mut mailbox = mailbox.fuse();
        let mut shutdown = shutdown.fuse();
        loop {
            futures::select! {
                maybe_msg = mailbox.next() => {
                   if let Some(msg) = maybe_msg {
                       self.handle_msg(msg).await;
                   }
                }
                _ = shutdown => {
                    break;
                }
            }
        }
    }

    async fn handle_msg(&mut self, msg: Msg<ReqT, RespT>) {
        match msg {
            Msg::Call { msg, tx } => {
                let resp = self.inner.handle_call(msg).await;
                respond_with(tx, resp);
            }
            Msg::Cast { msg } => self.inner.handle_cast(msg).await,
        }
    }
}

//impl <S, M> Clone for ActorHandle<S, M> where S: Clone {
//    fn clone(&self) -> Self {
//        Self {
//            inner: self.inner.clone(),
//        }
//    }
//}
