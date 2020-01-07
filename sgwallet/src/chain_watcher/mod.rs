// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, format_err, Result};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use libra_logger::prelude::*;
use sgchain::star_chain_client::ChainClient;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
mod txn_stream;
use async_trait::async_trait;
use coerce_rt::{
    actor,
    actor::{
        context::{ActorContext, ActorHandlerContext},
        message::Message,
        ActorRef,
    },
};
use std::time::Duration;
use tokio::time::interval;

use uuid::Uuid;

pub use txn_stream::TransactionWithInfo;

pub type Interest = Box<dyn Fn(&TransactionWithInfo) -> bool + Send + Sync>;

#[derive(Clone)]
pub struct ChainWatcherHandle {
    actor_ref: ActorRef<ChainWatcher>,
}

impl ChainWatcherHandle {
    /// add a oneshot interest
    pub async fn add_interest_oneshot(
        &self,
        interest: Interest,
    ) -> Result<oneshot::Receiver<TransactionWithInfo>> {
        let (tx, rx) = oneshot::channel();
        let succ = self
            .actor_ref
            .clone()
            .send(AddInterest {
                tag: Uuid::new_v4(),
                interest,
                sink: Trans::Oneshot(tx),
            })
            .await
            .map_err(|_| format_err!("task is already stopped"))?;
        if succ {
            Ok(rx)
        } else {
            bail!("an interest with same tag already exists");
        }
    }

    /// add interest on txn stream
    pub async fn add_interest(
        &self,
        interest: Interest,
    ) -> Result<mpsc::Receiver<TransactionWithInfo>> {
        let (tx, rx) = mpsc::channel(1024);

        let succ = self
            .actor_ref
            .clone()
            .send(AddInterest {
                tag: Uuid::new_v4(),
                interest,
                sink: Trans::Mpsc(tx),
            })
            .await
            .map_err(|_| format_err!("task is already stopped"))?;

        if succ {
            Ok(rx)
        } else {
            bail!("an interest with same tag already exists");
        }
    }

    pub async fn stop(mut self) {
        let _ = self.actor_ref.stop().await;
    }
}

struct AddInterest {
    tag: Uuid,
    interest: Interest,
    sink: Trans,
}
impl actor::message::Message for AddInterest {
    type Result = bool;
}

struct Cleanup;
impl actor::message::Message for Cleanup {
    type Result = ();
}

struct NewTxn {
    txn: Result<TransactionWithInfo>,
}
impl actor::message::Message for NewTxn {
    type Result = ();
}

pub struct ChainWatcher {
    chain_client: Arc<dyn ChainClient>,
    down_streams: HashMap<Uuid, DownStream>,
    start_version: u64,
    limit: u64,
}
impl ChainWatcher {
    pub fn new(chain_client: Arc<dyn ChainClient>, start_version: u64, limit: u64) -> Self {
        Self {
            chain_client,
            down_streams: HashMap::new(),
            start_version,
            limit,
        }
    }

    pub async fn start(self, mut context: ActorContext) -> Result<ChainWatcherHandle> {
        let actor_ref = context.new_actor(self).await?;
        Ok(ChainWatcherHandle { actor_ref })
    }
}

#[async_trait]
impl actor::Actor for ChainWatcher {
    async fn started(&mut self, ctx: &mut ActorHandlerContext) {
        // TODO: spawn txn stream
        let my_actor_id = ctx.actor_id().clone();
        let mut myself = ctx
            .actor_context_mut()
            .get_actor::<Self>(my_actor_id.clone())
            .await
            .unwrap();
        let mut myself_clone = myself.clone();

        let mut cleanup_interval = interval(Duration::from_secs(2)).fuse();
        tokio::task::spawn(async move {
            while let Some(_) = cleanup_interval.next().await {
                if let Err(_e) = myself.notify(Cleanup).await {
                    info!("parent task is gone, stop now");
                    break;
                }
            }
        });
        let mut txn_stream = txn_stream::TxnStream::new_from_chain_client(
            self.chain_client.clone(),
            self.start_version,
            self.limit,
        );

        tokio::task::spawn(async move {
            while let Some(txn) = txn_stream.next().await {
                if let Err(_e) = myself_clone.send(NewTxn { txn }).await {
                    info!("parent task is gone, stop now");
                    break;
                }
            }
        });

        info!("chain watcher started, id: {}", ctx.actor_id());
    }

    async fn stopped(&mut self, ctx: &mut ActorHandlerContext) {
        info!("chain watcher stopped, id : {}", ctx.actor_id());
    }
}

#[async_trait]
impl actor::message::Handler<AddInterest> for ChainWatcher {
    async fn handle(
        &mut self,
        message: AddInterest,
        _ctx: &mut ActorHandlerContext,
    ) -> <AddInterest as Message>::Result {
        let AddInterest {
            tag,
            interest,
            sink,
        } = message;
        self.add_interest(tag, interest, sink)
    }
}

#[async_trait]
impl actor::message::Handler<Cleanup> for ChainWatcher {
    async fn handle(
        &mut self,
        _message: Cleanup,
        _ctx: &mut ActorHandlerContext,
    ) -> <Cleanup as Message>::Result {
        self.down_streams.retain(|_, v| !v.is_closed());
    }
}
#[async_trait]
impl actor::message::Handler<NewTxn> for ChainWatcher {
    async fn handle(
        &mut self,
        message: NewTxn,
        _ctx: &mut ActorHandlerContext,
    ) -> <NewTxn as Message>::Result {
        let NewTxn { txn } = message;
        self.handle_txn(txn).await;
    }
}

impl ChainWatcher {
    async fn handle_txn(&mut self, txn: Result<TransactionWithInfo>) {
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

    fn add_interest(&mut self, tag: Uuid, interest: Interest, sink: Trans) -> bool {
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
    Oneshot(oneshot::Sender<TransactionWithInfo>),
    Mpsc(mpsc::Sender<TransactionWithInfo>),
}
