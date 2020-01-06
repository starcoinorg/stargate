mod ant_generator_test;
mod path_finder;
mod seed_generator;

use anyhow::*;
use tokio::runtime::Handle;

use sgwallet::wallet::{Wallet, WalletHandle};
use std::sync::Arc;

use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::stream::StreamExt;
use libra_crypto::hash::CryptoHash;
use libra_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    test_utils::KeyPair,
    Uniform,
};
use libra_logger::prelude::*;
use libra_tools::tempdir::TempPath;
use libra_types::account_address::AccountAddress;
use path_finder::{PathStore, SeedManager};
use seed_generator::{generate_random_u128, SValueGenerator};

use rand::prelude::*;
use sgchain::star_chain_client::ChainClient;
use sgchain::star_chain_client::{faucet_async_2, MockChainClient};

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use network::{build_network_service, NetworkMessage};
use sg_config::config::NetworkConfig;

use futures::compat::Stream01CompatExt;
use sgtypes::system_event::Event;

use futures_timer::Delay;
use libra_crypto::HashValue;
use router::{message_processor::*, Router, TableRouter};
use sgtypes::message::{
    AntFinalMessage, AntQueryMessage, BalanceQueryResponse, ExchangeSeedMessageRequest,
    ExchangeSeedMessageResponse, RouterNetworkMessage,
};
use sgtypes::s_value::SValue;
use stats::{DirectedChannel, PaymentInfo, Stats};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;

pub struct MixRouter {
    ant_router: AntRouter,
    table_router: TableRouter,
    executor: Handle,
    network_receiver: Option<UnboundedReceiver<(AccountAddress, RouterNetworkMessage)>>,
    ant_network_sender: UnboundedSender<(AccountAddress, RouterNetworkMessage)>,
    table_network_sender: UnboundedSender<(AccountAddress, RouterNetworkMessage)>,
    control_receiver: Option<UnboundedReceiver<Event>>,
    control_sender: UnboundedSender<Event>,
    stats_mgr: Arc<Stats>,
}

impl MixRouter {
    pub fn new(
        chain_client: Arc<dyn ChainClient>,
        executor: Handle,
        network_sender: UnboundedSender<(AccountAddress, RouterNetworkMessage)>,
        network_receiver: UnboundedReceiver<(AccountAddress, RouterNetworkMessage)>,
        wallet: Arc<WalletHandle>,
        stats_mgr: Arc<Stats>,
        default_future_timeout: u64,
    ) -> Self {
        let (ant_network_sender, ant_network_receiver) = futures::channel::mpsc::unbounded();
        let (table_network_sender, table_network_receiver) = futures::channel::mpsc::unbounded();
        let (control_sender, control_receiver) = futures::channel::mpsc::unbounded();

        let ant_router = AntRouter::new(
            executor.clone(),
            network_sender.clone(),
            ant_network_receiver,
            wallet.clone(),
            default_future_timeout / 2,
            stats_mgr.clone(),
        );

        let table_router = TableRouter::new(
            chain_client,
            executor.clone(),
            wallet,
            network_sender.clone(),
            table_network_receiver,
            stats_mgr.clone(),
        );

        Self {
            table_router,
            ant_router,
            executor,
            network_receiver: Some(network_receiver),
            ant_network_sender,
            table_network_sender,
            control_sender,
            control_receiver: Some(control_receiver),
            stats_mgr,
        }
    }

    pub fn start(&mut self) -> Result<()> {
        let network_receiver = self.network_receiver.take().expect("already taken");
        let control_receiver = self.control_receiver.take().expect("already taken");

        self.table_router.start()?;
        self.ant_router.start()?;

        self.executor.spawn(Self::start_network(
            network_receiver,
            self.table_network_sender.clone(),
            self.ant_network_sender.clone(),
            control_receiver,
        ));

        Ok(())
    }

    async fn start_network(
        mut network_receiver: UnboundedReceiver<(AccountAddress, RouterNetworkMessage)>,
        table_network_sender: UnboundedSender<(AccountAddress, RouterNetworkMessage)>,
        ant_network_sender: UnboundedSender<(AccountAddress, RouterNetworkMessage)>,
        mut control_receiver: UnboundedReceiver<Event>,
    ) -> Result<()> {
        loop {
            futures::select! {
                (peer_id, network_message) = network_receiver.select_next_some() =>{
                    Self::handle_network_message(
                        table_network_sender.clone(),
                        ant_network_sender.clone(),
                        peer_id,
                        network_message,
                       )?;
                },
                _ = control_receiver.select_next_some() =>{
                    info!("shutdown");
                    break;
                },
            }
        }
        Ok(())
    }

    fn handle_network_message(
        table_network_sender: UnboundedSender<(AccountAddress, RouterNetworkMessage)>,
        ant_network_sender: UnboundedSender<(AccountAddress, RouterNetworkMessage)>,
        peer_id: AccountAddress,
        network_message: RouterNetworkMessage,
    ) -> Result<()> {
        match network_message {
            RouterNetworkMessage::BalanceQueryRequest(message) => {
                table_network_sender.unbounded_send((
                    peer_id,
                    RouterNetworkMessage::BalanceQueryRequest(message),
                ))?;
            }
            RouterNetworkMessage::BalanceQueryResponse(message) => {
                table_network_sender.unbounded_send((
                    peer_id,
                    RouterNetworkMessage::BalanceQueryResponse(message),
                ))?;
            }
            RouterNetworkMessage::ExchangeSeedMessageRequest(message) => {
                ant_network_sender.unbounded_send((
                    peer_id,
                    RouterNetworkMessage::ExchangeSeedMessageRequest(message),
                ))?;
            }
            RouterNetworkMessage::ExchangeSeedMessageResponse(message) => {
                ant_network_sender.unbounded_send((
                    peer_id,
                    RouterNetworkMessage::ExchangeSeedMessageResponse(message),
                ))?;
            }
            RouterNetworkMessage::AntQueryMessage(message) => {
                ant_network_sender
                    .unbounded_send((peer_id, RouterNetworkMessage::AntQueryMessage(message)))?;
            }
            RouterNetworkMessage::AntFinalMessage(message) => {
                ant_network_sender
                    .unbounded_send((peer_id, RouterNetworkMessage::AntFinalMessage(message)))?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Router for MixRouter {
    async fn find_path_by_addr(
        &self,
        start: AccountAddress,
        end: AccountAddress,
    ) -> Result<Vec<BalanceQueryResponse>> {
        match self.table_router.find_path_by_addr(start, end).await {
            Ok(r) => {
                if r.len() > 0 {
                    return Ok(r);
                }
            }
            Err(e) => {
                warn!(
                    "could not find path by table router from {},to {},e is {}",
                    start, end, e
                );
            }
        }
        return self.ant_router.find_path_by_addr(start, end).await;
    }

    fn stats(&self, channel: DirectedChannel, payment_info: PaymentInfo) -> Result<()> {
        self.stats_mgr.stats(channel, payment_info)?;
        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        self.table_router.shutdown().await?;
        self.ant_router.shutdown().await?;
        self.control_sender.unbounded_send(Event::SHUTDOWN)?;
        Ok(())
    }
}

pub struct AntRouter {
    executor: Handle,
    command_sender: UnboundedSender<RouterCommand>,
    inner: Option<AntRouterInner>,
    network_receiver: Option<UnboundedReceiver<(AccountAddress, RouterNetworkMessage)>>,
    command_receiver: Option<UnboundedReceiver<RouterCommand>>,
    control_receiver: Option<UnboundedReceiver<Event>>,
    control_sender: UnboundedSender<Event>,
    stats_mgr: Arc<Stats>,
}

struct AntRouterInner {
    network_sender: UnboundedSender<(AccountAddress, RouterNetworkMessage)>,
    wallet: Arc<WalletHandle>,
    seed_manager: SeedManager,
    message_processor: MessageProcessor<RouterNetworkMessage>,
    default_future_timeout: AtomicU64,
    executor: Handle,
    stats_mgr: Arc<Stats>,
    path_store: PathStore,
}

enum RouterCommand {
    FindPath {
        start: AccountAddress,
        end: AccountAddress,
        responder: futures::channel::oneshot::Sender<Result<Vec<BalanceQueryResponse>>>,
    },
}

impl AntRouter {
    pub fn new(
        executor: Handle,
        network_sender: UnboundedSender<(AccountAddress, RouterNetworkMessage)>,
        network_receiver: UnboundedReceiver<(AccountAddress, RouterNetworkMessage)>,
        wallet: Arc<WalletHandle>,
        default_future_timeout: u64,
        stats_mgr: Arc<Stats>,
    ) -> Self {
        let (command_sender, command_receiver) = futures::channel::mpsc::unbounded();
        let (control_sender, control_receiver) = futures::channel::mpsc::unbounded();

        let message_processor = MessageProcessor::new();
        let inner = AntRouterInner {
            wallet,
            network_sender,
            seed_manager: SeedManager::new(),
            message_processor,
            default_future_timeout: AtomicU64::new(default_future_timeout),
            executor: executor.clone(),
            stats_mgr: stats_mgr.clone(),
            path_store: PathStore::new(),
        };
        Self {
            executor,
            command_sender,
            network_receiver: Some(network_receiver),
            command_receiver: Some(command_receiver),
            control_sender,
            control_receiver: Some(control_receiver),
            inner: Some(inner),
            stats_mgr,
        }
    }

    pub fn start(&mut self) -> Result<()> {
        let inner = self.inner.take().expect("should have inner");
        let network_receiver = self
            .network_receiver
            .take()
            .expect("should have network receiver");
        let command_receiver = self
            .command_receiver
            .take()
            .expect("should have command receiver");
        let control_receiver = self.control_receiver.take().expect("already taken");
        let inner = Arc::new(inner);
        self.executor.spawn(AntRouterInner::start(
            self.executor.clone(),
            inner,
            network_receiver,
            command_receiver,
            control_receiver,
        ));
        Ok(())
    }
}

#[async_trait]
impl Router for AntRouter {
    async fn find_path_by_addr(
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

        resp_receiver.await?
    }

    fn stats(&self, channel: DirectedChannel, payment_info: PaymentInfo) -> Result<()> {
        self.stats_mgr.stats(channel, payment_info)?;
        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        self.control_sender.unbounded_send(Event::SHUTDOWN)?;
        Ok(())
    }
}

impl AntRouterInner {
    async fn start(
        executor: Handle,
        router_inner: Arc<AntRouterInner>,
        mut network_receiver: UnboundedReceiver<(AccountAddress, RouterNetworkMessage)>,
        mut command_receiver: UnboundedReceiver<RouterCommand>,
        mut control_receiver: UnboundedReceiver<Event>,
    ) {
        loop {
            futures::select! {
                message = command_receiver.select_next_some() => {
                    executor.spawn(Self::handle_command(router_inner.clone(),message));
                },
                (peer_id, network_message) = network_receiver.select_next_some() =>{
                    executor.spawn(Self::handle_network_msg(
                        router_inner.clone(),
                        peer_id,
                        network_message,
                       ));
                },
                _ = control_receiver.select_next_some() =>{
                    info!("shutdown");
                    break;
                },
            }
        }
    }

    async fn handle_command(
        router_inner: Arc<AntRouterInner>,
        command: RouterCommand,
    ) -> Result<()> {
        match command {
            RouterCommand::FindPath {
                start,
                end,
                responder,
            } => {
                return router_inner.find_path(start, end, responder).await;
            }
        }
    }

    async fn handle_network_msg(
        router_inner: Arc<AntRouterInner>,
        peer_id: AccountAddress,
        msg: RouterNetworkMessage,
    ) -> Result<()> {
        match msg {
            RouterNetworkMessage::ExchangeSeedMessageResponse(response) => {
                return router_inner
                    .handle_exchange_seed_message_response(response)
                    .await;
            }
            RouterNetworkMessage::AntFinalMessage(response) => {
                return router_inner.handle_ant_final_message(response).await;
            }
            RouterNetworkMessage::ExchangeSeedMessageRequest(request) => {
                return router_inner
                    .handle_exchange_seed_message_request(request, peer_id)
                    .await;
            }
            RouterNetworkMessage::AntQueryMessage(message) => {
                return router_inner.handle_ant_query_message(message).await;
            }
            _ => bail!("should not be here"),
        }
    }

    async fn find_path(
        &self,
        start: AccountAddress,
        end: AccountAddress,
        responder: futures::channel::oneshot::Sender<Result<Vec<BalanceQueryResponse>>>,
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
            .add_future(request_hash.clone(), tx.clone())
            .await;
        self.future_timeout(
            request_hash,
            self.default_future_timeout.load(Ordering::Relaxed),
        );
        let response = message_future.await?;

        match response {
            RouterNetworkMessage::ExchangeSeedMessageResponse(resp) => {
                let s_generator = SValueGenerator::new(resp.sender_seed, resp.receiver_seed);
                let s = s_generator.get_s(true);

                self.send_ant_query_message(s, start.clone(), vec![])
                    .await?;

                Delay::new(Duration::from_millis(
                    self.default_future_timeout.load(Ordering::Relaxed),
                ))
                .await;

                let r = s_generator.get_r();
                let paths = self.path_store.take_path(&r).await;
                match paths {
                    Some(resp) => {
                        respond_with(responder, self.find_path_by_pressure(resp, start, end));
                    }
                    None => {
                        respond_with(responder, Err(anyhow!("no path found")));
                        warn!("no path found");
                        return Ok(());
                    }
                }
            }
            _ => {
                respond_with(responder, Err(anyhow!("no path found")));
                warn!("no path found");
                return Ok(());
            }
        }

        Ok(())
    }

    fn find_path_by_pressure(
        &self,
        paths: Vec<AntFinalMessage>,
        start: AccountAddress,
        end: AccountAddress,
    ) -> Result<Vec<BalanceQueryResponse>> {
        let mut balance_map = HashMap::new();
        let mut min_pressure = std::i128::MAX;
        for path in paths.into_iter() {
            let balances = self.format_response_list(path, start, end);
            let mut pressure: i128 = 0;
            for balance in balances.iter() {
                pressure =
                    pressure + balance.total_pay_amount as i128 + balance.remote_balance as i128
                        - balance.local_balance as i128;
            }
            balance_map.insert(pressure, balances);
            if pressure < min_pressure {
                min_pressure = pressure;
            }
        }
        match balance_map.remove(&min_pressure) {
            Some(t) => Ok(t),
            None => bail!("no path find"),
        }
    }

    fn format_response_list(
        &self,
        resp: AntFinalMessage,
        start: AccountAddress,
        end: AccountAddress,
    ) -> Vec<BalanceQueryResponse> {
        let mut result = Vec::new();
        let mut seed = start;
        let mut done = false;
        let mut list = resp.balance_query_response_list;
        while !done {
            match self.find_response(seed, &mut list) {
                Some(balance_response) => {
                    if balance_response.remote_addr == end {
                        done = true;
                    }
                    seed = balance_response.remote_addr.clone();
                    result.push(balance_response);
                }
                None => {
                    done = true;
                }
            }
        }
        result
    }

    fn find_response(
        &self,
        local: AccountAddress,
        response_list: &mut Vec<BalanceQueryResponse>,
    ) -> Option<BalanceQueryResponse> {
        let mut index = 0;
        let mut find = false;
        for (i, response) in response_list.iter().enumerate() {
            if response.local_addr == local || response.remote_addr == local {
                index = i;
                find = true;
            }
        }
        if find {
            let response = response_list.remove(index);
            if response.remote_addr == local {
                return Some(response.revert());
            } else {
                return Some(response);
            }
        }
        None
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
        self.path_store.add_path(response.r_value, response).await?;
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

        let response = ExchangeSeedMessageResponse::new(request.sender_seed, receiver_seed);
        self.send_ant_query_message(s, peer_id.clone(), vec![])
            .await?;
        self.network_sender.unbounded_send((
            peer_id,
            RouterNetworkMessage::ExchangeSeedMessageResponse(response),
        ))?;

        Ok(())
    }

    async fn send_ant_query_message(
        &self,
        s: SValue,
        peer_id: AccountAddress,
        balance_list: Vec<BalanceQueryResponse>,
    ) -> Result<()> {
        let all_channels = self.wallet.get_all_channels().await?;

        let mut already_send_set = HashSet::new();
        for balance_query_response in &balance_list {
            already_send_set.insert(balance_query_response.remote_addr.clone());
            already_send_set.insert(balance_query_response.local_addr.clone());
        }
        for participant in all_channels.iter() {
            if already_send_set.contains(participant) {
                continue;
            }
            let mut balance_list_clone = balance_list.clone();
            let total_amount = self
                .stats_mgr
                .back_pressure(&(self.wallet.account(), participant.clone()))
                .await?;

            let balance_query_response = BalanceQueryResponse::new(
                self.wallet.account(),
                participant.clone(),
                self.wallet.channel_balance(participant.clone()).await?,
                self.wallet
                    .participant_channel_balance(participant.clone())
                    .await?,
                total_amount,
            );
            balance_list_clone.push(balance_query_response);
            let ant_query_message = AntQueryMessage::new(s, peer_id, balance_list_clone);
            self.network_sender.unbounded_send((
                participant.clone(),
                RouterNetworkMessage::AntQueryMessage(ant_query_message),
            ))?;
        }
        Ok(())
    }

    async fn handle_ant_query_message(&self, message: AntQueryMessage) -> Result<()> {
        let query_message = message.clone();
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
                self.send_ant_query_message(
                    query_message.s_value,
                    query_message.sender_addr,
                    query_message.balance_query_response_list,
                )
                .await?;
            }
        }
        Ok(())
    }

    fn future_timeout(&self, hash: HashValue, timeout: u64) {
        if timeout == 0 {
            return;
        }
        let processor = self.message_processor.clone();
        let task = async move {
            Delay::new(Duration::from_millis(timeout)).await;
            processor.remove_future(hash).await;
        };
        self.executor.spawn(task);
    }
}

fn respond_with<T>(responder: futures::channel::oneshot::Sender<T>, msg: T) {
    if let Err(_t) = responder.send(msg) {
        error!("fail to send back response, receiver is dropped",);
    };
}

#[allow(dead_code)]
async fn _gen_wallet(
    client: Arc<MockChainClient>,
) -> Result<(
    Arc<WalletHandle>,
    AccountAddress,
    Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
)> {
    let amount: u64 = 10_000_000;
    let mut rng: StdRng = SeedableRng::seed_from_u64(_get_unix_ts()); //SeedableRng::from_seed([0; 32]);
    let keypair = Arc::new(KeyPair::generate_for_testing(&mut rng));
    let account_address = AccountAddress::from_public_key(&keypair.public_key);

    faucet_async_2(client.as_ref().clone(), account_address, amount)
        .await
        .unwrap();
    let store_path = TempPath::new();
    let wallet =
        Wallet::new_with_client(account_address, keypair.clone(), client, store_path.path())?;

    let wallet = wallet.start().await?;
    wallet.enable_channel().await?;
    Ok((Arc::new(wallet), account_address, keypair))
}

async fn _delay(duration: Duration) {
    tokio::time::delay_for(duration).await;
}

async fn _open_channel(
    sender_wallet: Arc<WalletHandle>,
    receiver_wallet: Arc<WalletHandle>,
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
fn mix_router_test() {
    use anyhow::Error;
    use libra_config::utils::get_available_port;
    use libra_logger::prelude::*;
    use sgchain::star_chain_client::MockChainClient;
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    libra_logger::init_for_e2e_testing();
    let mut rt = Runtime::new().unwrap();
    let executor = rt.handle().clone();

    let (mock_chain_service, _handle) = MockChainClient::new();
    let client = Arc::new(mock_chain_service);

    let (wallet1, addr1, keypair1) = rt.block_on(_gen_wallet(client.clone())).unwrap();
    let (wallet2, addr2, keypair2) = rt.block_on(_gen_wallet(client.clone())).unwrap();
    let (wallet3, addr3, keypair3) = rt.block_on(_gen_wallet(client.clone())).unwrap();

    let _wallet1 = wallet1.clone();
    let _wallet2 = wallet2.clone();
    let _wallet3 = wallet3.clone();
    let _client = client.clone();

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
    let (rtx1, rrx1) = _prepare_network(tx1, rx1, executor.clone());
    let mut router1 = MixRouter::new(
        client.clone(),
        executor.clone(),
        rtx1,
        rrx1,
        wallet1.clone(),
        Arc::new(Stats::new(executor.clone())),
        5000,
    );
    router1.start().unwrap();

    let (_network2, tx2, rx2, close_tx2) = build_network_service(&network_config2, keypair2);
    let _identify2 = _network2.identify();
    let (rtx2, rrx2) = _prepare_network(tx2, rx2, executor.clone());
    let mut router2 = MixRouter::new(
        client.clone(),
        executor.clone(),
        rtx2,
        rrx2,
        wallet2.clone(),
        Arc::new(Stats::new(executor.clone())),
        5000,
    );
    router2.start().unwrap();

    let (_network3, tx3, rx3, close_tx3) = build_network_service(&network_config3, keypair3);
    let _identify3 = _network3.identify();
    let (rtx3, rrx3) = _prepare_network(tx3, rx3, executor.clone());
    let mut router3 = MixRouter::new(
        client.clone(),
        executor.clone(),
        rtx3,
        rrx3,
        wallet3.clone(),
        Arc::new(Stats::new(executor.clone())),
        5000,
    );
    router3.start().unwrap();

    let router1 = Arc::new(router1);
    let router2 = Arc::new(router2);
    let router3 = Arc::new(router3);

    let _router1 = router1.clone();
    let _router2 = router2.clone();
    let _router3 = router3.clone();

    let f = async move {
        _open_channel(wallet1.clone(), wallet2.clone(), 100000, 100000).await?;
        _open_channel(wallet2.clone(), wallet3.clone(), 100000, 100000).await?;

        _delay(Duration::from_millis(5000)).await;

        let path = router1
            .find_path_by_addr(addr1.clone(), addr3.clone())
            .await?;

        assert_eq!(path.len(), 2);
        assert_eq!(path.get(0).expect("should have").local_addr, addr1.clone());
        assert_eq!(path.get(1).expect("should have").remote_addr, addr3.clone());

        let path = router1
            .find_path_by_addr(addr1.clone(), addr2.clone())
            .await?;

        assert_eq!(path.len(), 1);
        assert_eq!(path.get(0).expect("should have").local_addr, addr1.clone());
        assert_eq!(path.get(0).expect("should have").remote_addr, addr2.clone());

        router1.shutdown().await?;
        router2.shutdown().await?;
        router3.shutdown().await?;

        close_tx1.send(()).unwrap();
        close_tx2.send(()).unwrap();
        close_tx3.send(()).unwrap();

        wallet1.stop().await?;
        wallet2.stop().await?;
        wallet3.stop().await?;

        Ok::<_, Error>(())
    };

    rt.block_on(f).unwrap();

    drop(rt);

    //    _ant_router1.shutdown().unwrap();
    //    _table_router1.shutdown().unwrap();
    //
    //    _ant_router2.shutdown().unwrap();
    //    _table_router2.shutdown().unwrap();
    //
    //    _ant_router3.shutdown().unwrap();
    //    _table_router3.shutdown().unwrap();

    debug!("here");
}

#[test]
fn ant_router_test() {
    use anyhow::Error;
    use libra_config::utils::get_available_port;
    use libra_logger::prelude::*;
    use sgchain::star_chain_client::MockChainClient;
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    libra_logger::init_for_e2e_testing();
    let mut rt = Runtime::new().unwrap();
    let executor = rt.handle().clone();

    let (mock_chain_service, _handle) = MockChainClient::new();
    let client = Arc::new(mock_chain_service);

    let (wallet1, addr1, keypair1) = rt.block_on(_gen_wallet(client.clone())).unwrap();
    let (wallet2, addr2, keypair2) = rt.block_on(_gen_wallet(client.clone())).unwrap();
    let (wallet3, _addr3, keypair3) = rt.block_on(_gen_wallet(client.clone())).unwrap();
    let (wallet4, addr4, keypair4) = rt.block_on(_gen_wallet(client.clone())).unwrap();
    let (wallet5, addr5, keypair5) = rt.block_on(_gen_wallet(client.clone())).unwrap();

    let _wallet1 = wallet1.clone();
    let _wallet2 = wallet2.clone();
    let _wallet3 = wallet3.clone();
    let _wallet4 = wallet4.clone();
    let _wallet5 = wallet5.clone();
    let _client = client.clone();

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

    let network_config4 = _create_node_network_config(
        format!("/ip4/127.0.0.1/tcp/{}", get_available_port()),
        vec![seed.clone()],
    );

    let network_config5 = _create_node_network_config(
        format!("/ip4/127.0.0.1/tcp/{}", get_available_port()),
        vec![seed.clone()],
    );

    let (_network1, tx1, rx1, close_tx1) = build_network_service(&network_config1, keypair1);
    let _identify1 = _network1.identify();
    let (rtx1, rrx1) = _prepare_network(tx1, rx1, executor.clone());
    let mut router1 = AntRouter::new(
        executor.clone(),
        rtx1,
        rrx1,
        wallet1.clone(),
        5000,
        Arc::new(Stats::new(executor.clone())),
    );
    router1.start().unwrap();

    let (_network2, tx2, rx2, close_tx2) = build_network_service(&network_config2, keypair2);
    let _identify2 = _network2.identify();
    let (rtx2, rrx2) = _prepare_network(tx2, rx2, executor.clone());
    let mut router2 = AntRouter::new(
        executor.clone(),
        rtx2,
        rrx2,
        wallet2.clone(),
        5000,
        Arc::new(Stats::new(executor.clone())),
    );
    router2.start().unwrap();

    let (_network3, tx3, rx3, close_tx3) = build_network_service(&network_config3, keypair3);
    let _identify3 = _network3.identify();
    let (rtx3, rrx3) = _prepare_network(tx3, rx3, executor.clone());
    let mut router3 = AntRouter::new(
        executor.clone(),
        rtx3,
        rrx3,
        wallet3.clone(),
        5000,
        Arc::new(Stats::new(executor.clone())),
    );
    router3.start().unwrap();

    let (_network4, tx4, rx4, close_tx4) = build_network_service(&network_config4, keypair4);
    let _identify4 = _network4.identify();
    let (rtx4, rrx4) = _prepare_network(tx4, rx4, executor.clone());
    let mut router4 = AntRouter::new(
        executor.clone(),
        rtx4,
        rrx4,
        wallet4.clone(),
        5000,
        Arc::new(Stats::new(executor.clone())),
    );
    router4.start().unwrap();

    let (_network5, tx5, rx5, close_tx5) = build_network_service(&network_config5, keypair5);
    let _identify5 = _network5.identify();
    let (rtx5, rrx5) = _prepare_network(tx5, rx5, executor.clone());
    let mut router5 = AntRouter::new(
        executor.clone(),
        rtx5,
        rrx5,
        wallet5.clone(),
        5000,
        Arc::new(Stats::new(executor.clone())),
    );
    router5.start().unwrap();

    let router1 = Arc::new(router1);
    let router2 = Arc::new(router2);
    let router3 = Arc::new(router3);
    let router4 = Arc::new(router4);
    let router5 = Arc::new(router5);

    let _router1 = router1.clone();
    let _router2 = router2.clone();
    let _router3 = router3.clone();
    let _router4 = router4.clone();
    let _router5 = router5.clone();

    let f = async move {
        _open_channel(wallet1.clone(), wallet2.clone(), 100000, 100000).await?;
        _open_channel(wallet2.clone(), wallet3.clone(), 100000, 100000).await?;
        _open_channel(wallet3.clone(), wallet4.clone(), 100000, 100000).await?;

        _delay(Duration::from_millis(5000)).await;

        let path = router1
            .find_path_by_addr(addr1.clone(), addr4.clone())
            .await?;

        assert_eq!(path.len(), 3);
        assert_eq!(path.get(0).expect("should have").local_addr, addr1.clone());
        assert_eq!(path.get(2).expect("should have").remote_addr, addr4.clone());

        let path = router1
            .find_path_by_addr(addr1.clone(), addr2.clone())
            .await?;

        assert_eq!(path.len(), 1);
        assert_eq!(path.get(0).expect("should have").local_addr, addr1.clone());
        assert_eq!(path.get(0).expect("should have").remote_addr, addr2.clone());

        let path = router1
            .find_path_by_addr(addr1.clone(), addr5.clone())
            .await;
        match path {
            Ok(_) => assert_eq!(1, 2),
            Err(_) => assert_eq!(1, 1),
        }

        router1.shutdown().await?;
        router2.shutdown().await?;
        router3.shutdown().await?;
        router4.shutdown().await?;
        router5.shutdown().await?;

        close_tx1.send(()).unwrap();
        close_tx2.send(()).unwrap();
        close_tx3.send(()).unwrap();
        close_tx4.send(()).unwrap();
        close_tx5.send(()).unwrap();

        wallet1.stop().await?;
        wallet2.stop().await?;
        wallet3.stop().await?;
        wallet4.stop().await?;
        wallet5.stop().await?;

        Ok::<_, Error>(())
    };

    rt.block_on(f).unwrap();
    drop(rt);

    debug!("here");
}

fn _prepare_network(
    tx: futures_01::sync::mpsc::UnboundedSender<NetworkMessage>,
    rx: futures_01::sync::mpsc::UnboundedReceiver<NetworkMessage>,
    executor: Handle,
) -> (
    UnboundedSender<(AccountAddress, RouterNetworkMessage)>,
    UnboundedReceiver<(AccountAddress, RouterNetworkMessage)>,
) {
    let (inbound_sender, inbound_receiver) = futures::channel::mpsc::unbounded();
    let (outbound_sender, outbound_receiver) = futures::channel::mpsc::unbounded();

    executor.spawn(_receive_router_message(rx, inbound_sender));
    executor.spawn(_send_router_message(outbound_receiver, tx));

    (outbound_sender, inbound_receiver)
}

async fn _send_router_message(
    mut rx: UnboundedReceiver<(AccountAddress, RouterNetworkMessage)>,
    tx: futures_01::sync::mpsc::UnboundedSender<NetworkMessage>,
) {
    while let Some((peer_id, message)) = rx.next().await {
        tx.unbounded_send(NetworkMessage {
            peer_id,
            data: message.into_proto_bytes().unwrap(),
        })
        .unwrap();
    }
}

async fn _receive_router_message(
    rx: futures_01::sync::mpsc::UnboundedReceiver<NetworkMessage>,
    tx: UnboundedSender<(AccountAddress, RouterNetworkMessage)>,
) {
    let mut rx = rx.compat();
    while let Some(Ok(s)) = rx.next().await {
        tx.unbounded_send((
            s.peer_id,
            RouterNetworkMessage::from_proto_bytes(s.data).unwrap(),
        ))
        .unwrap();
    }
}
