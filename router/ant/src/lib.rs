mod ant_generator_test;
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
use path_finder::SeedManager;

pub struct AntRouter {
    executor: Handle,
    control_sender: UnboundedSender<Event>,
    network_sender: UnboundedSender<NetworkMessage>,
    inner: Option<AntRouterInner>,
}

struct AntRouterInner {
    control_receiver: UnboundedReceiver<Event>,
    network_receiver: UnboundedReceiver<NetworkMessage>,
    wallet: Arc<Wallet>,
    seed_manager: SeedManager,
}

impl AntRouter {
    pub fn new(
        executor: Handle,
        network_sender: UnboundedSender<NetworkMessage>,
        network_receiver: UnboundedReceiver<NetworkMessage>,
        wallet: Arc<Wallet>,
    ) -> Self {
        let (control_sender, control_receiver) = futures::channel::mpsc::unbounded();
        let inner = AntRouterInner {
            wallet,
            network_receiver,
            control_receiver,
            seed_manager: SeedManager::new(),
        };
        Self {
            executor,
            control_sender,
            network_sender,
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

    async fn handle_network_msg(&self, msg: NetworkMessage) {}
}
