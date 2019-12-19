mod ant_generator_test;
mod message_processor;
mod path_finder;
mod seed_generator;

use anyhow::*;
use network::NetworkMessage;
use sgtypes::system_event::Event;
use tokio::runtime::Handle;

use sgwallet::wallet::Wallet;
use std::sync::Arc;

use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::stream::StreamExt;
use libra_logger::prelude::*;
use libra_types::account_address::AccountAddress;
use message_processor::{MessageFuture, MessageProcessor};
use path_finder::SeedManager;
use seed_generator::{generate_random_u128, SValueGenerator};

use sgtypes::message::{
    ExchangeSeedMessageRequest, ExchangeSeedMessageResponse, RouterNetworkMessage,
};

pub struct AntRouter {
    executor: Handle,
    control_sender: UnboundedSender<Event>,
    inner: Option<AntRouterInner>,
}

struct AntRouterInner {
    control_receiver: UnboundedReceiver<Event>,
    network_receiver: UnboundedReceiver<RouterNetworkMessage>,
    network_sender: UnboundedSender<RouterNetworkMessage>,
    wallet: Arc<Wallet>,
    seed_manager: SeedManager,
    message_processor: MessageProcessor<RouterNetworkMessage>,
}

impl AntRouter {
    pub fn new(
        executor: Handle,
        network_sender: UnboundedSender<RouterNetworkMessage>,
        network_receiver: UnboundedReceiver<RouterNetworkMessage>,
        wallet: Arc<Wallet>,
    ) -> Self {
        let (control_sender, control_receiver) = futures::channel::mpsc::unbounded();
        let message_processor = MessageProcessor::new();
        let inner = AntRouterInner {
            wallet,
            network_receiver,
            control_receiver,
            network_sender,
            seed_manager: SeedManager::new(),
            message_processor,
        };
        Self {
            executor,
            control_sender,
            inner: Some(inner),
        }
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.control_sender.unbounded_send(Event::SHUTDOWN)?;
        Ok(())
    }

    pub fn start(&mut self) -> Result<()> {
        let inner = self.inner.take().expect("should have inner");
        self.executor.spawn(inner.start());
        Ok(())
    }

    pub async fn find_path_by_addr(
        &self,
        start: AccountAddress,
        end: AccountAddress,
    ) -> Result<Option<Vec<AccountAddress>>> {
        Ok(None)
    }
}

impl AntRouterInner {
    async fn start(mut self) {
        loop {
            futures::select! {
                network_message = self.network_receiver.select_next_some()=>{
                    self.handle_network_msg(network_message).await;
                },
                _ = self.control_receiver.select_next_some() =>{
                    info!("shutdown");
                    break;
                },
            }
        }
    }

    async fn handle_network_msg(&self, msg: RouterNetworkMessage) {}

    async fn find_path(&self, start: AccountAddress, end: AccountAddress) -> Result<()> {
        let sender_seed = generate_random_u128();
        let message = ExchangeSeedMessageRequest::new(sender_seed);
        self.network_sender
            .unbounded_send(RouterNetworkMessage::ExchangeSeedMessageRequest(message))?;
        Ok(())
    }
}
