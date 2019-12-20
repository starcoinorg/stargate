mod ant_generator_test;
mod message_processor;
mod path_finder;
mod seed_generator;

use anyhow::*;
use sgtypes::system_event::Event;
use tokio::runtime::Handle;

use sgwallet::wallet::Wallet;
use std::sync::Arc;

use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::stream::StreamExt;
use libra_crypto::hash::CryptoHash;
use libra_logger::prelude::*;
use libra_types::account_address::AccountAddress;
use message_processor::{MessageFuture, MessageProcessor};
use path_finder::SeedManager;
use seed_generator::{generate_random_u128, SValueGenerator};

use sgtypes::message::{
    AntFinalMessage, AntQueryMessage, BalanceQueryResponse, ExchangeSeedMessageRequest,
    ExchangeSeedMessageResponse, RouterNetworkMessage,
};

pub struct AntRouter {
    executor: Handle,
    control_sender: UnboundedSender<Event>,
    command_sender: UnboundedSender<RouterCommand>,
    inner: Option<AntRouterInner>,
    control_receiver: Option<UnboundedReceiver<Event>>,
    network_receiver: Option<UnboundedReceiver<(AccountAddress, RouterNetworkMessage)>>,
    command_receiver: Option<UnboundedReceiver<RouterCommand>>,
}

struct AntRouterInner {
    network_sender: UnboundedSender<(AccountAddress, RouterNetworkMessage)>,
    wallet: Arc<Wallet>,
    seed_manager: SeedManager,
    message_processor: MessageProcessor<RouterNetworkMessage>,
}

enum RouterCommand {
    FindPath {
        start: AccountAddress,
        end: AccountAddress,
        responder: futures::channel::oneshot::Sender<Vec<BalanceQueryResponse>>,
    },
}

impl AntRouter {
    pub fn new(
        executor: Handle,
        network_sender: UnboundedSender<(AccountAddress, RouterNetworkMessage)>,
        network_receiver: UnboundedReceiver<(AccountAddress, RouterNetworkMessage)>,
        wallet: Arc<Wallet>,
    ) -> Self {
        let (control_sender, control_receiver) = futures::channel::mpsc::unbounded();
        let (command_sender, command_receiver) = futures::channel::mpsc::unbounded();

        let message_processor = MessageProcessor::new();
        let inner = AntRouterInner {
            wallet,
            network_sender,
            seed_manager: SeedManager::new(),
            message_processor,
        };
        Self {
            executor,
            control_sender,
            command_sender,
            network_receiver: Some(network_receiver),
            control_receiver: Some(control_receiver),
            command_receiver: Some(command_receiver),
            inner: Some(inner),
        }
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.control_sender.unbounded_send(Event::SHUTDOWN)?;
        Ok(())
    }

    pub fn start(&mut self) -> Result<()> {
        let inner = self.inner.take().expect("should have inner");
        let network_receiver = self
            .network_receiver
            .take()
            .expect("should have network receiver");
        let control_receiver = self
            .control_receiver
            .take()
            .expect("should have control receiver");
        let command_receiver = self
            .command_receiver
            .take()
            .expect("should have command receiver");
        let inner = Arc::new(inner);
        self.executor.spawn(AntRouterInner::start_network(
            inner.clone(),
            network_receiver,
            control_receiver,
        ));
        self.executor
            .spawn(AntRouterInner::start_command(inner, command_receiver));
        Ok(())
    }

    pub async fn find_path_by_addr(
        &self,
        start: AccountAddress,
        end: AccountAddress,
    ) -> Result<Vec<BalanceQueryResponse>> {
        let (resp_sender, resp_receiver) = futures::channel::oneshot::channel();

        self.command_sender
            .unbounded_send(RouterCommand::FindPath {
                start,
                end,
                responder: resp_sender,
            })?;

        Ok(resp_receiver.await?)
    }
}

impl AntRouterInner {
    async fn start_network(
        router_inner: Arc<AntRouterInner>,
        mut network_receiver: UnboundedReceiver<(AccountAddress, RouterNetworkMessage)>,
        mut control_receiver: UnboundedReceiver<Event>,
    ) {
        loop {
            futures::select! {
                (peer_id,network_message) = network_receiver.select_next_some()=>{
                    router_inner.handle_network_msg(peer_id,network_message).await.unwrap();
                },
                _ = control_receiver.select_next_some() =>{
                    info!("shutdown");
                    break;
                },
            }
        }
    }

    async fn start_command(
        router_inner: Arc<AntRouterInner>,
        mut command_receiver: UnboundedReceiver<RouterCommand>,
    ) {
        loop {
            futures::select! {
                command = command_receiver.select_next_some()=>{
                    router_inner.handle_command(command).await.unwrap();
                },
            }
        }
    }

    async fn handle_command(&self, command: RouterCommand) -> Result<()> {
        match command {
            RouterCommand::FindPath {
                start,
                end,
                responder,
            } => {
                return self.find_path(start, end, responder).await;
            }
        }
    }

    async fn handle_network_msg(
        &self,
        peer_id: AccountAddress,
        msg: RouterNetworkMessage,
    ) -> Result<()> {
        match msg {
            RouterNetworkMessage::ExchangeSeedMessageResponse(response) => {
                return self.handle_exchange_seed_message_response(response).await;
            }
            RouterNetworkMessage::AntFinalMessage(response) => {
                return self.handle_ant_final_message(response).await;
            }
            RouterNetworkMessage::ExchangeSeedMessageRequest(request) => {
                return self
                    .handle_exchange_seed_message_request(request, peer_id)
                    .await;
            }
            RouterNetworkMessage::AntQueryMessage(message) => {
                return self.handle_ant_query_message(message).await;
            }
        }
    }

    async fn find_path(
        &self,
        start: AccountAddress,
        end: AccountAddress,
        responder: futures::channel::oneshot::Sender<Vec<BalanceQueryResponse>>,
    ) -> Result<()> {
        let sender_seed = generate_random_u128();
        let message = ExchangeSeedMessageRequest::new(sender_seed);
        let request_hash = message.hash();
        self.network_sender.unbounded_send((
            end.clone(),
            RouterNetworkMessage::ExchangeSeedMessageRequest(message),
        ))?;

        let (tx, rx) = futures::channel::mpsc::channel(1);
        let message_future = MessageFuture::new(rx);
        self.message_processor
            .add_future(request_hash, tx.clone())
            .await;
        let response = message_future.await?;

        match response {
            RouterNetworkMessage::ExchangeSeedMessageResponse(resp) => {
                let s_generator = SValueGenerator::new(resp.sender_seed, resp.receiver_seed);
                let s = s_generator.get_s(true);

                let all_channels = self.wallet.get_all_channels().await?;
                for participant in all_channels.iter() {
                    let ant_query_message = AntQueryMessage::new(s, start, vec![]);
                    self.network_sender.unbounded_send((
                        participant.clone(),
                        RouterNetworkMessage::AntQueryMessage(ant_query_message),
                    ))?;
                }

                let (tx, rx) = futures::channel::mpsc::channel(1);
                let message_future = MessageFuture::new(rx);
                self.message_processor
                    .add_future(s_generator.get_r(), tx.clone())
                    .await;
                let response = message_future.await?;

                match response {
                    RouterNetworkMessage::AntFinalMessage(resp) => {
                        respond_with(responder, resp.balance_query_response_list);
                    }
                    _ => {
                        warn!("should not be here");
                        return Ok(());
                    }
                }
            }
            _ => {
                warn!("should not be here");
                return Ok(());
            }
        }

        Ok(())
    }

    async fn handle_exchange_seed_message_response(
        &self,
        response: ExchangeSeedMessageResponse,
    ) -> Result<()> {
        self.message_processor
            .send_response(
                response.request_hash(),
                RouterNetworkMessage::ExchangeSeedMessageResponse(response),
            )
            .await?;
        Ok(())
    }

    async fn handle_ant_final_message(&self, response: AntFinalMessage) -> Result<()> {
        self.message_processor
            .send_response(
                response.r_value,
                RouterNetworkMessage::AntFinalMessage(response),
            )
            .await?;
        Ok(())
    }

    async fn handle_exchange_seed_message_request(
        &self,
        request: ExchangeSeedMessageRequest,
        peer_id: AccountAddress,
    ) -> Result<()> {
        let receiver_seed = generate_random_u128();

        let s_generator = SValueGenerator::new(request.sender_seed, receiver_seed);
        let s = s_generator.get_s(false);

        let all_channels = self.wallet.get_all_channels().await?;
        for participant in all_channels.iter() {
            let ant_query_message = AntQueryMessage::new(s, peer_id.clone(), vec![]);
            self.network_sender.unbounded_send((
                participant.clone(),
                RouterNetworkMessage::AntQueryMessage(ant_query_message),
            ))?;
        }

        let response = ExchangeSeedMessageResponse::new(request.sender_seed, receiver_seed);
        self.network_sender.unbounded_send((
            peer_id,
            RouterNetworkMessage::ExchangeSeedMessageResponse(response),
        ))?;

        Ok(())
    }

    async fn handle_ant_query_message(&self, message: AntQueryMessage) -> Result<()> {
        match self
            .seed_manager
            .match_or_add(message.s_value, message.balance_query_response_list)
            .await
        {
            Some(t) => {
                let r = message.s_value.get_r();
                let final_message = AntFinalMessage::new(r, t);
                self.network_sender.unbounded_send((
                    message.sender_addr,
                    RouterNetworkMessage::AntFinalMessage(final_message),
                ))?;
            }
            None => {
                info!("waiting for match");
            }
        }
        Ok(())
    }
}

fn respond_with<T>(responder: futures::channel::oneshot::Sender<T>, msg: T) {
    if let Err(_t) = responder.send(msg) {
        error!("fail to send back response, receiver is dropped",);
    };
}
