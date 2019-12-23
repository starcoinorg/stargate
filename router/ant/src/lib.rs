mod ant_generator_test;
mod message_processor;
mod path_finder;
mod seed_generator;

use anyhow::*;
use sgtypes::system_event::Event;
use tokio::runtime::Handle;
use tokio::runtime::Runtime;

use sgwallet::wallet::Wallet;
use std::sync::Arc;

use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::{sink::SinkExt, stream::StreamExt};
use libra_crypto::hash::CryptoHash;
use libra_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    test_utils::KeyPair,
    Uniform,
};
use libra_logger::prelude::*;
use libra_tools::tempdir::TempPath;
use libra_types::account_address::AccountAddress;
use message_processor::{MessageFuture, MessageProcessor};
use path_finder::SeedManager;
use seed_generator::{generate_random_u128, SValueGenerator};

use rand::prelude::*;
use sgchain::star_chain_client::{faucet_async_2, MockChainClient};

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use network::{build_network_service, NetworkMessage};
use sg_config::config::NetworkConfig;

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

    pub async fn shutdown(&mut self) -> Result<()> {
        self.control_sender.unbounded_send(Event::SHUTDOWN)?;
        self.command_sender.close().await?;
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

fn _gen_wallet(
    executor: Handle,
    client: Arc<MockChainClient>,
) -> Result<(
    Arc<Wallet>,
    AccountAddress,
    Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
)> {
    let amount: u64 = 10_000_000;
    let mut rng: StdRng = SeedableRng::seed_from_u64(_get_unix_ts()); //SeedableRng::from_seed([0; 32]);
    let keypair = Arc::new(KeyPair::generate_for_testing(&mut rng));
    let account_address = AccountAddress::from_public_key(&keypair.public_key);
    let mut rt = Runtime::new().expect("faucet runtime err.");
    let f = async {
        faucet_async_2(client.as_ref().clone(), account_address, amount)
            .await
            .unwrap();
    };
    rt.block_on(f);
    let store_path = TempPath::new();
    let mut wallet =
        Wallet::new_with_client(account_address, keypair.clone(), client, store_path.path())
            .unwrap();
    wallet.start(&executor).unwrap();

    let f = async {
        wallet.enable_channel().await.unwrap();
    };
    rt.block_on(f);

    Ok((Arc::new(wallet), account_address, keypair))
}

async fn _delay(duration: Duration) {
    tokio::time::delay_for(duration).await;
}

async fn _open_channel(
    sender_wallet: Arc<Wallet>,
    receiver_wallet: Arc<Wallet>,
    sender_amount: u64,
    receiver_amount: u64,
) -> Result<u64> {
    let sender = sender_wallet.account();
    let receiver = receiver_wallet.account();
    let req = sender_wallet
        .open(receiver_wallet.account(), sender_amount, receiver_amount)
        .await?;
    let resp = receiver_wallet.verify_txn(sender, &req).await?;
    let resp = if let Some(t) = resp {
        t
    } else {
        receiver_wallet
            .approve_txn(sender, req.request_id())
            .await?
    };
    let _ = sender_wallet.verify_txn_response(receiver, &resp).await?;
    let sender_gas = sender_wallet.apply_txn(receiver, &resp).await?;
    let _receiver_gas = receiver_wallet.apply_txn(sender, &resp).await?;
    Ok(sender_gas)
}

fn _get_unix_ts() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_millis() as u64
}

fn _create_node_network_config(addr: String, seeds: Vec<String>) -> NetworkConfig {
    return NetworkConfig {
        listen: addr,
        seeds,
    };
}

fn _build_network(
    config: &NetworkConfig,
    keypair: Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
) {
    let (network, _tx, _rx, _close_tx) = build_network_service(config, keypair);
    let _identify = network.identify();
}

#[test]
fn ant_router_test() {
    use anyhow::Error;
    use libra_config::utils::get_available_port;
    use libra_logger::prelude::*;
    use sgchain::star_chain_client::MockChainClient;
    use std::sync::Arc;

    libra_logger::init_for_e2e_testing();
    let mut rt = Runtime::new().unwrap();
    let executor = rt.handle().clone();

    let (mock_chain_service, _handle) = MockChainClient::new();
    let client = Arc::new(mock_chain_service);

    let (wallet1, addr1, keypair1) = _gen_wallet(executor.clone(), client.clone()).unwrap();
    let (wallet2, _addr2, keypair2) = _gen_wallet(executor.clone(), client.clone()).unwrap();
    let (wallet3, _addr3, keypair3) = _gen_wallet(executor.clone(), client.clone()).unwrap();

    let _wallet1 = wallet1.clone();
    let _wallet2 = wallet2.clone();
    let _wallet3 = wallet3.clone();

    let network_config1 = _create_node_network_config(
        format!("/ip4/127.0.0.1/tcp/{}", get_available_port()),
        vec![],
    );

    let addr1_hex = hex::encode(addr1);
    let seed = format!("{}/p2p/{}", &network_config1.listen, addr1_hex);

    let network_config2 = _create_node_network_config(
        format!("/ip4/127.0.0.1/tcp/{}", get_available_port()),
        vec![seed.clone()],
    );

    let network_config3 = _create_node_network_config(
        format!("/ip4/127.0.0.1/tcp/{}", get_available_port()),
        vec![seed.clone()],
    );

    let (_network1, tx1, rx1, close_tx1) = build_network_service(&network_config1, keypair1);
    let _identify1 = _network1.identify();

    let (_network2, tx2, rx2, close_tx2) = build_network_service(&network_config2, keypair2);
    let _identify2 = _network2.identify();

    let (_network3, tx3, rx3, close_tx3) = build_network_service(&network_config3, keypair3);
    let _identify3 = _network3.identify();

    let f = async move {
        _open_channel(wallet1.clone(), wallet2.clone(), 100000, 100000).await?;
        _open_channel(wallet2.clone(), wallet3.clone(), 100000, 100000).await?;

        _delay(Duration::from_millis(5000)).await;

        wallet1.stop().await?;
        wallet2.stop().await?;
        wallet3.stop().await?;
        Ok::<_, Error>(())
    };

    rt.block_on(f).unwrap();

    debug!("here");
}

async fn _send_router_message(
    tx: UnboundedSender<NetworkMessage>,
    peer_id: AccountAddress,
    message: RouterNetworkMessage,
) -> Result<()> {
    tx.unbounded_send(NetworkMessage {
        peer_id,
        data: message.into_proto_bytes()?,
    })?;
    Ok(())
}

async fn _receive_router_message(
    mut rx: UnboundedReceiver<NetworkMessage>,
    tx: UnboundedSender<(AccountAddress, RouterNetworkMessage)>,
) {
    while let Some(s) = rx.next().await {
        tx.unbounded_send((
            s.peer_id,
            RouterNetworkMessage::from_proto_bytes(s.data).unwrap(),
        ))
        .unwrap();
    }
}
