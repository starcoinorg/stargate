// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::chain_watcher::txn_stream::TxnStream;
use anyhow::bail;
use anyhow::Result;
use futures::channel::mpsc;
use futures::channel::oneshot;
use futures::{FutureExt, SinkExt, StreamExt};
use libra_logger::prelude::*;
use libra_types::transaction::Transaction;
use sgchain::star_chain_client::ChainClient;
use std::collections::HashMap;
use std::sync::Arc;
mod txn_stream;
pub type Interest = Box<dyn Fn(&Transaction) -> bool + Send>;

pub struct ChainWatcher {
    chain_client: Arc<dyn ChainClient>,
    interests: HashMap<Vec<u8>, Interest>,
    down_streams: HashMap<Vec<u8>, mpsc::Sender<Transaction>>,
    mailbox: mpsc::Receiver<InnerMsg>,
    mailbox_sender: mpsc::Sender<InnerMsg>,
}

impl ChainWatcher {
    pub fn new(chain_client: Arc<dyn ChainClient>) -> Self {
        let (tx, rx) = mpsc::channel(1024);
        Self {
            chain_client,
            interests: HashMap::new(),
            down_streams: HashMap::new(),
            mailbox: rx,
            mailbox_sender: tx,
        }
    }

    pub fn start(
        self,
        executor: tokio::runtime::Handle,
        start_version: u64,
        limit: u64,
    ) -> Result<ChainWatcherHandle> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = ChainWatcherHandle {
            mail_sender: self.mailbox_sender.clone(),
            shutdown_tx: Some(shutdown_tx),
        };
        let txn_stream = txn_stream::TxnStream::new_from_chain_client(
            self.chain_client.clone(),
            start_version,
            limit,
        );

        executor.spawn(self.inner_start(txn_stream, shutdown_rx));
        Ok(handle)
    }
}

pub struct ChainWatcherHandle {
    mail_sender: mpsc::Sender<InnerMsg>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl ChainWatcherHandle {
    pub async fn add_interest(
        &self,
        tag: Vec<u8>,
        interest: Interest,
    ) -> Result<mpsc::Receiver<Transaction>> {
        let (tx, rx) = mpsc::channel(1024);
        call(
            self.mail_sender.clone(),
            Request::AddInterest {
                tag,
                interest,
                down_stream: tx,
            },
        )
        .await?;

        Ok(rx)
    }
    pub async fn remove_interest(&self, tag: Vec<u8>) -> Result<()> {
        call(self.mail_sender.clone(), Request::RemoveInterest { tag }).await?;
        Ok(())
    }

    pub fn stop(&mut self) {
        // if send return err, it means receiver already dropped.
        if let Some(tx) = self.shutdown_tx.take() {
            if let Err(_) = tx.send(()) {
                warn!("receiver end of shutdown is already dropped");
            }
        }
    }
}

#[derive(Debug)]
enum Msg<ReqT, RespT> {
    Call {
        msg: ReqT,
        tx: oneshot::Sender<RespT>,
    },
    Cast {
        msg: ReqT,
    },
}

enum Request {
    AddInterest {
        tag: Vec<u8>,
        interest: Interest,
        down_stream: mpsc::Sender<Transaction>,
    },
    RemoveInterest {
        tag: Vec<u8>,
    },
}
#[derive(Debug)]
enum Response {
    AddInterestResp,
    RemoveInterestResp,
}

type InnerMsg = Msg<Request, Response>;

impl ChainWatcher {
    async fn inner_start(mut self, txn_stream: TxnStream, shutdown_rx: oneshot::Receiver<()>) {
        let mut fused_txn_stream = txn_stream.fuse();
        let mut fused_shutdown_tx = shutdown_rx.fuse();
        loop {
            futures::select! {
                maybe_msg = self.mailbox.next() => {
                   if let Some(msg) = maybe_msg {
                       self.handle_msg(msg).await;
                   }
                }
                maybe_txn = fused_txn_stream.next() => {
                    if let Some(txn) = maybe_txn {
                        self.handle_txn(txn).await;
                    }
                }
                _ = fused_shutdown_tx => {
                    break;
                }
            }
        }

        info!("chain watcher terminated");
    }

    async fn handle_txn(&mut self, txn: Result<Transaction>) {
        match txn {
            Err(e) => error!("fail to get txn from chain, e: {:#?}", e),
            Ok(t) => {
                let interested_stream = {
                    let mut interested_stream = HashMap::new();
                    for (tag, down_stream) in self.down_streams.iter() {
                        match self.interests.get(tag) {
                            None => error!("should contain interest"),
                            Some(interest) => {
                                if interest(&t) {
                                    interested_stream.insert(tag.clone(), down_stream.clone());
                                }
                            }
                        }
                    }
                    interested_stream
                };

                for (tag, mut s) in interested_stream.into_iter() {
                    if let Err(_) = s.send(t.clone()).await {
                        // drop disconnected interests
                        self.remove_interest(&tag);
                    }
                }
            }
        }
    }

    async fn handle_msg(&mut self, msg: InnerMsg) {
        match msg {
            Msg::Call { msg, tx } => self.handle_call(msg, tx).await,
            Msg::Cast { msg } => self.handle_cast(msg).await,
        }
    }
    async fn handle_call(&mut self, msg: Request, responder: oneshot::Sender<Response>) {
        let resp = match msg {
            Request::AddInterest {
                tag,
                interest,
                down_stream,
            } => {
                self.add_interest(tag, interest, down_stream);
                Response::AddInterestResp
            }
            Request::RemoveInterest { tag } => {
                self.remove_interest(&tag);
                Response::RemoveInterestResp
            }
        };
        respond_with(responder, resp);
    }

    async fn handle_cast(&mut self, _msg: Request) {
        unimplemented!()
    }

    fn add_interest(&mut self, tag: Vec<u8>, interest: Interest, tx: mpsc::Sender<Transaction>) {
        self.interests.insert(tag.clone(), interest);
        self.down_streams.insert(tag.clone(), tx);
    }

    fn remove_interest(&mut self, tag: &Vec<u8>) {
        self.interests.remove(tag);
        self.down_streams.remove(tag);
    }
}

async fn call<ReqT, RespT>(
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

fn respond_with<T>(responder: oneshot::Sender<T>, msg: T) {
    if let Err(_t) = responder.send(msg) {
        error!("fail to send back response, receiver is dropped",);
    };
}
