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
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
mod txn_stream;
use super::utils::{call, cast, respond_with, Msg};
use std::time::Duration;
use tokio::time::interval;

pub type Interest = Box<dyn Fn(&Transaction) -> bool + Send>;

pub struct ChainWatcherHandle {
    mail_sender: mpsc::Sender<InnerMsg>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl ChainWatcherHandle {
    /// add a oneshot interest
    pub async fn add_interest_oneshot(
        &self,
        tag: Vec<u8>,
        interest: Interest,
    ) -> Result<oneshot::Receiver<Transaction>> {
        let (tx, rx) = oneshot::channel();
        call(
            self.mail_sender.clone(),
            Request::AddInterest {
                tag,
                interest,
                sink: Trans::Oneshot(tx),
            },
        )
        .await?;

        Ok(rx)
    }

    /// add interest on txn stream
    pub async fn add_interest(
        &self,
        tag: Vec<u8>,
        interest: Interest,
    ) -> Result<mpsc::Receiver<Transaction>> {
        let (tx, rx) = mpsc::channel(1024);
        let resp = call(
            self.mail_sender.clone(),
            Request::AddInterest {
                tag,
                interest,
                sink: Trans::Mpsc(tx),
            },
        )
        .await?;
        let Response::AddInterestResp(succ) = resp;
        if succ {
            Ok(rx)
        } else {
            bail!("an interest with same tag already exists");
        }
    }

    pub fn remove_interest(&self, tag: Vec<u8>) -> Result<()> {
        cast(self.mail_sender.clone(), Request::RemoveInterest { tag })
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

impl Drop for ChainWatcherHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

enum Request {
    AddInterest {
        tag: Vec<u8>,
        interest: Interest,
        sink: Trans,
    },
    RemoveInterest {
        tag: Vec<u8>,
    },
}
#[derive(Debug)]
enum Response {
    AddInterestResp(bool),
}

type InnerMsg = Msg<Request, Response>;

pub struct ChainWatcher {
    chain_client: Arc<dyn ChainClient>,
    down_streams: HashMap<Vec<u8>, DownStream>,
    mailbox: mpsc::Receiver<InnerMsg>,
    mailbox_sender: mpsc::Sender<InnerMsg>,
}

impl ChainWatcher {
    pub fn new(chain_client: Arc<dyn ChainClient>) -> Self {
        let (tx, rx) = mpsc::channel(1024);
        Self {
            chain_client,
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

impl ChainWatcher {
    async fn inner_start(mut self, txn_stream: TxnStream, shutdown_rx: oneshot::Receiver<()>) {
        let mut fused_txn_stream = txn_stream.fuse();
        let mut fused_shutdown_tx = shutdown_rx.fuse();
        let mut cleanup_interval = interval(Duration::from_secs(2)).fuse();
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
                maybe_interval = cleanup_interval.next() => {
                    if let Some(_) = maybe_interval {
                        self.handle_cleanup_interval().await;
                    }
                }
                _ = fused_shutdown_tx => {
                    break;
                }
            }
        }

        info!("chain watcher terminated");
    }

    /// Drop down streams that is already closed periodicly.
    async fn handle_cleanup_interval(&mut self) {
        self.down_streams.retain(|_, v| match v.sink {
            Trans::Oneshot(ref s) => !s.is_canceled(),
            Trans::Mpsc(ref s) => !s.is_closed(),
        });
    }

    async fn handle_txn(&mut self, txn: Result<Transaction>) {
        match txn {
            Err(e) => error!("fail to get txn from chain, e: {:#?}", e),
            Ok(t) => {
                let interested_stream = {
                    let mut interested_stream = HashSet::new();
                    for (tag, down_stream) in self.down_streams.iter() {
                        if (down_stream.interest)(&t) {
                            interested_stream.insert(tag.clone());
                        }
                    }
                    interested_stream
                };

                for tag in interested_stream.into_iter() {
                    let mut down_stream = self
                        .down_streams
                        .remove(&tag)
                        .expect("down stream should exists");

                    if down_stream.is_oneshot() {
                        match down_stream.sink {
                            Trans::Oneshot(s) => {
                                if let Err(_) = s.send(t.clone()) {
                                    warn!("receiver already dropped");
                                }
                            }
                            _ => unreachable!(),
                        }
                        continue;
                    }

                    match &mut down_stream.sink {
                        Trans::Mpsc(s) => {
                            if let Err(_) = s.send(t.clone()).await {
                                // drop disconnected interests
                                info!("receiver dropped, remove the interest directly");
                                continue;
                            }
                        }
                        _ => unreachable!(),
                    }

                    self.down_streams.insert(tag, down_stream);
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
                sink,
            } => {
                let success = self.add_interest(tag, interest, sink);
                Response::AddInterestResp(success)
            }
            _ => unreachable!(),
        };
        respond_with(responder, resp);
    }

    async fn handle_cast(&mut self, msg: Request) {
        match msg {
            Request::RemoveInterest { tag } => {
                self.remove_interest(&tag);
            }
            _ => unreachable!(),
        }
    }

    fn add_interest(&mut self, tag: Vec<u8>, interest: Interest, sink: Trans) -> bool {
        match self.down_streams.remove(&tag) {
            Some(s) if !s.is_closed() => {
                self.down_streams.insert(tag, s);
                false
            }
            _ => {
                self.down_streams.insert(tag, DownStream { interest, sink });
                true
            }
        }
    }

    fn remove_interest(&mut self, tag: &Vec<u8>) {
        self.down_streams.remove(tag);
    }
}

struct DownStream {
    interest: Interest,
    sink: Trans,
}

impl DownStream {
    fn is_oneshot(&self) -> bool {
        match &self.sink {
            Trans::Oneshot(_) => true,
            _ => false,
        }
    }
    fn is_closed(&self) -> bool {
        match &self.sink {
            Trans::Oneshot(s) => s.is_canceled(),
            Trans::Mpsc(s) => s.is_closed(),
        }
    }
}

enum Trans {
    Oneshot(oneshot::Sender<Transaction>),
    Mpsc(mpsc::Sender<Transaction>),
}
