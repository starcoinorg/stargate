use anyhow::*;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::lock::Mutex;
use futures::stream::StreamExt;
use libra_crypto::HashValue;
use libra_logger::prelude::*;
use libra_types::account_address::AccountAddress;
use sgtypes::system_event::Event;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::runtime::Handle;

pub struct Stats {
    executor: Handle,
    inner: Arc<StatsInner>,
    data_receiver: Option<UnboundedReceiver<(DirectedChannel, PaymentInfo)>>,
    data_sender: UnboundedSender<(DirectedChannel, PaymentInfo)>,
    control_receiver: Option<UnboundedReceiver<Event>>,
    control_sender: UnboundedSender<Event>,
}

struct StatsInner {
    user_channel_stats: Mutex<HashMap<DirectedChannel, ChannelStats>>,
}
struct ChannelStats {
    payment_data: Mutex<HashMap<HashValue, u64>>,
}

pub enum PayEnum {
    Paying,
    Payed,
}

pub type DirectedChannel = (AccountAddress, AccountAddress);

pub type PaymentInfo = (HashValue, u64, PayEnum);

impl ChannelStats {
    fn new() -> Self {
        Self {
            payment_data: Mutex::new(HashMap::new()),
        }
    }

    async fn insert(&self, amount: u64, hash_value: HashValue) {
        self.payment_data.lock().await.insert(hash_value, amount);
    }

    async fn remove(&self, hash_value: HashValue) {
        self.payment_data.lock().await.remove(&hash_value);
    }

    async fn sum(&self) -> u64 {
        let payment_data = self.payment_data.lock().await;
        let mut result = 0;
        for (_, amount) in payment_data.iter() {
            result += amount;
        }
        result
    }
}

impl Stats {
    pub fn new(executor: Handle) -> Self {
        let (control_sender, control_receiver) = futures::channel::mpsc::unbounded();
        let (data_sender, data_receiver) = futures::channel::mpsc::unbounded();

        let inner = StatsInner {
            user_channel_stats: Mutex::new(HashMap::new()),
        };
        Self {
            data_sender,
            data_receiver: Some(data_receiver),
            inner: Arc::new(inner),
            control_sender,
            control_receiver: Some(control_receiver),
            executor,
        }
    }

    pub async fn back_pressure(&self, channel: &DirectedChannel) -> Result<u64> {
        self.inner.payment_pressure(channel).await
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

    pub fn stats(&self, channel: DirectedChannel, payment_info: PaymentInfo) -> Result<()> {
        self.data_sender.unbounded_send((channel, payment_info))?;
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
        mut data_receiver: UnboundedReceiver<(DirectedChannel, PaymentInfo)>,
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
        payment_info: PaymentInfo,
    ) -> Result<()> {
        match payment_info.2 {
            PayEnum::Paying => match inner.user_channel_stats.lock().await.get(&channel) {
                Some(channel_stats) => {
                    channel_stats.insert(payment_info.1, payment_info.0).await;
                }
                None => {
                    let channel_stats = ChannelStats::new();
                    channel_stats.insert(payment_info.1, payment_info.0).await;
                    inner.insert_channel_stats(channel, channel_stats).await;
                }
            },
            PayEnum::Payed => match inner.user_channel_stats.lock().await.get(&channel) {
                Some(channel_stats) => {
                    channel_stats.remove(payment_info.0).await;
                }
                None => {}
            },
        }
        Ok(())
    }

    async fn insert_channel_stats(&self, channel: DirectedChannel, stats: ChannelStats) {
        self.user_channel_stats.lock().await.insert(channel, stats);
    }

    async fn payment_pressure(&self, channel: &DirectedChannel) -> Result<u64> {
        match self.user_channel_stats.lock().await.get(channel) {
            Some(channel_stats) => Ok(channel_stats.sum().await),
            None => Ok(0),
        }
    }
}
