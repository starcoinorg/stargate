use anyhow::*;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::lock::Mutex;
use futures::stream::StreamExt;
use libra_logger::prelude::*;
use libra_types::account_address::AccountAddress;
use sgtypes::system_event::Event;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::runtime::Handle;

pub struct Stats {
    executor: Handle,
    inner: Arc<StatsInner>,
    data_receiver: Option<UnboundedReceiver<(DirectedChannel, u64)>>,
    control_receiver: Option<UnboundedReceiver<Event>>,
    control_sender: UnboundedSender<Event>,
}

struct StatsInner {
    user_channel_stats: Mutex<HashMap<DirectedChannel, ChannelStats>>,
}
struct ChannelStats {
    payment_data: Mutex<BTreeMap<u64, u64>>,
}

pub type DirectedChannel = (AccountAddress, AccountAddress);

impl ChannelStats {
    pub fn new() -> Self {
        Self {
            payment_data: Mutex::new(BTreeMap::new()),
        }
    }

    pub async fn insert(&self, timestamp: u64, amount: u64) {
        self.payment_data.lock().await.insert(timestamp, amount);
    }
}

impl Stats {
    pub fn new(executor: Handle, data_receiver: UnboundedReceiver<(DirectedChannel, u64)>) -> Self {
        let (control_sender, control_receiver) = futures::channel::mpsc::unbounded();

        let inner = StatsInner {
            user_channel_stats: Mutex::new(HashMap::new()),
        };
        Self {
            data_receiver: Some(data_receiver),
            inner: Arc::new(inner),
            control_sender,
            control_receiver: Some(control_receiver),
            executor,
        }
    }

    pub fn back_pressure(&self) -> Result<()> {
        Ok(())
    }

    pub fn start(&mut self) -> Result<()> {
        let data_receiver = self.data_receiver.take().expect("already taken");
        let control_receiver = self.control_receiver.take().expect("already taken");

        self.executor.spawn(StatsInner::start(
            self.inner.clone(),
            data_receiver,
            control_receiver,
        ));

        Ok(())
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.control_sender.unbounded_send(Event::SHUTDOWN)?;
        Ok(())
    }
}

impl StatsInner {
    async fn start(
        inner: Arc<StatsInner>,
        mut data_receiver: UnboundedReceiver<(DirectedChannel, u64)>,
        mut control_receiver: UnboundedReceiver<Event>,
    ) -> Result<()> {
        loop {
            futures::select! {
                (channel, amount) = data_receiver.select_next_some() =>{
                    Self::handle_data_message(
                        inner.clone(),
                        channel,
                        amount,
                       ).await?;
                },
                _ = control_receiver.select_next_some() =>{
                    info!("shutdown");
                    break;
                },
            }
        }
        Ok(())
    }

    async fn handle_data_message(
        inner: Arc<StatsInner>,
        channel: DirectedChannel,
        amount: u64,
    ) -> Result<()> {
        match inner.user_channel_stats.lock().await.get(&channel) {
            Some(channel_stats) => {
                channel_stats.insert(get_unix_ts(), amount).await;
            }
            None => {
                let channel_stats = ChannelStats::new();
                channel_stats.insert(get_unix_ts(), amount).await;
                inner.insert_channel_stats(channel, channel_stats).await;
            }
        }
        Ok(())
    }

    async fn insert_channel_stats(&self, channel: DirectedChannel, stats: ChannelStats) {
        self.user_channel_stats.lock().await.insert(channel, stats);
    }
}

fn get_unix_ts() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_millis() as u64
}
