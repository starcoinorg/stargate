pub mod message_processor;

use anyhow::{bail, ensure, Result};

use crate::message_processor::*;
use async_trait::async_trait;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::channel::oneshot;
use futures::compat::Stream01CompatExt;
use futures::stream::StreamExt;
use graphdb::{edge::Edge, graph_store::GraphStore, vertex::Vertex};
use libra_crypto::hash::CryptoHash;
use libra_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    test_utils::KeyPair,
    Uniform,
};
use libra_logger::prelude::*;
use libra_tools::tempdir::TempPath;
use libra_types::account_address::AccountAddress;
use network::{build_network_service, NetworkMessage};
use rand::prelude::*;
use sg_config::config::NetworkConfig;
use sgchain::star_chain_client::ChainClient;
use sgchain::star_chain_client::{faucet_async_2, MockChainClient};
use sgtypes::message::{BalanceQueryRequest, BalanceQueryResponse, RouterNetworkMessage};
use sgtypes::system_event::Event;
use sgwallet::wallet::{Wallet, WalletHandle};
use sgwallet::{get_channel_events, ChannelChangeEvent};
use stats::{DirectedChannel, PaymentInfo, Stats};
use std::collections::{HashMap, HashSet};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::runtime::Handle;

#[async_trait]
pub trait Router: Send + Sync {
    async fn find_path_by_addr(
        &self,
        start: AccountAddress,
        end: AccountAddress,
    ) -> Result<Vec<BalanceQueryResponse>>;

    fn stats(&self, channel: DirectedChannel, payment_info: PaymentInfo) -> Result<()>;

    async fn shutdown(&self) -> Result<()>;
}

pub struct TableRouter {
    inner: Option<RouterInner>,
    executor: Handle,
    sender: UnboundedSender<RouterMessage>,
    control_sender: UnboundedSender<Event>,
    network_receiver: Option<UnboundedReceiver<(AccountAddress, RouterNetworkMessage)>>,
    receiver: Option<UnboundedReceiver<RouterMessage>>,
    control_receiver: Option<UnboundedReceiver<Event>>,
    chain_client: Arc<dyn ChainClient>,
    stats_mgr: Arc<Stats>,
}

struct RouterInner {
    graph_store: GraphStore,
    network_sender: UnboundedSender<(AccountAddress, RouterNetworkMessage)>,
    wallet: Arc<WalletHandle>,
    message_processor: MessageProcessor<RouterNetworkMessage>,
    stats_mgr: Arc<Stats>,
}

enum RouterMessage {
    FindPath {
        start: Vertex,
        end: Vertex,
        responder: oneshot::Sender<Result<Vec<BalanceQueryResponse>>>,
    },
}

impl TableRouter {
    pub fn new(
        chain_client: Arc<dyn ChainClient>,
        executor: Handle,
        wallet: Arc<WalletHandle>,
        network_sender: UnboundedSender<(AccountAddress, RouterNetworkMessage)>,
        network_receiver: UnboundedReceiver<(AccountAddress, RouterNetworkMessage)>,
        stats_mgr: Arc<Stats>,
    ) -> Self {
        let (sender, receiver) = futures::channel::mpsc::unbounded();
        let (control_sender, control_receiver) = futures::channel::mpsc::unbounded();
        let message_processor = MessageProcessor::new();

        let inner = RouterInner {
            wallet,
            network_sender,
            message_processor,
            graph_store: GraphStore::new(false, None).unwrap(),
            stats_mgr: stats_mgr.clone(),
        };
        Self {
            chain_client,
            inner: Some(inner),
            executor,
            sender,
            control_sender,
            receiver: Some(receiver),
            network_receiver: Some(network_receiver),
            control_receiver: Some(control_receiver),
            stats_mgr,
        }
    }

    async fn find_path(&self, start: Vertex, end: Vertex) -> Result<Vec<BalanceQueryResponse>> {
        let (responder, resp_receiver) = futures::channel::oneshot::channel();

        info!("find by path {:?},{:?}", start, end);
        self.sender.unbounded_send(RouterMessage::FindPath {
            start,
            end,
            responder,
        })?;

        let result = resp_receiver.await?;
        info!("find by path result {:?}", result);
        result
    }

    pub fn start(&mut self) -> Result<()> {
        let inner = self.inner.take().expect("should have inner");
        let network_receiver = self
            .network_receiver
            .take()
            .expect("should have network receiver");
        let chain_client = self.chain_client.clone();
        let receiver = self.receiver.take().expect("should have");
        let control_receiver = self.control_receiver.take().expect("should have");

        let inner = Arc::new(inner);

        self.executor.spawn(RouterInner::start(
            self.executor.clone(),
            inner,
            chain_client,
            control_receiver,
            receiver,
            network_receiver,
        ));
        Ok(())
    }
}

#[async_trait]
impl Router for TableRouter {
    async fn find_path_by_addr(
        &self,
        start: AccountAddress,
        end: AccountAddress,
    ) -> Result<Vec<BalanceQueryResponse>> {
        let start_node = Vertex::new_with_bi_type(start);
        let end_node = Vertex::new_with_bi_type(end);
        let vertexes = self.find_path(start_node, end_node).await;
        vertexes
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

impl RouterInner {
    async fn start(
        executor: Handle,
        inner: Arc<RouterInner>,
        chain_client: Arc<dyn ChainClient>,
        mut control_receiver: UnboundedReceiver<Event>,
        mut command_receiver: UnboundedReceiver<RouterMessage>,
        mut network_receiver: UnboundedReceiver<(AccountAddress, RouterNetworkMessage)>,
    ) {
        let client = chain_client.clone();

        let stream = get_channel_events(client, 0, 100).fuse();
        let mut stream = Box::pin(stream);

        loop {
            futures::select! {
                (peer_id, network_message) = network_receiver.select_next_some() =>{
                    executor.spawn(Self::handle_router_network_msg(
                    inner.clone(),
                    peer_id,
                    network_message,
                    ));
                }
                command = command_receiver.select_next_some() => {
                    executor.spawn(Self::handle_router_msg(inner.clone(), command));
                },
                message = stream.select_next_some() => {
                    executor.spawn(Self::handle_stream(inner.clone(),message));
                },
                _ = control_receiver.select_next_some() =>{
                    info!("shutdown stream");
                    break;
                },
            }
        }
        drop(stream);
    }

    async fn handle_router_network_msg(
        inner: Arc<RouterInner>,
        peer_id: AccountAddress,
        msg: RouterNetworkMessage,
    ) {
        match msg {
            RouterNetworkMessage::BalanceQueryRequest(request) => {
                return inner
                    .handle_balance_query_request(peer_id, request)
                    .await
                    .unwrap();
            }
            RouterNetworkMessage::BalanceQueryResponse(message) => {
                return inner
                    .handle_balance_query_response(peer_id, message)
                    .await
                    .unwrap();
            }
            _ => {}
        }
    }

    async fn handle_router_msg(inner: Arc<RouterInner>, msg: RouterMessage) -> Result<()> {
        match msg {
            RouterMessage::FindPath {
                start,
                end,
                responder,
            } => {
                let paths = inner.graph_store.find_all_path(&start, &end, 5)?;

                info!("path is {:?}", paths);
                let result = match paths {
                    Some(t) => inner.find_path(t).await?,
                    None => vec![],
                };
                respond_with(responder, Ok(result));
            }
        }
        Ok(())
    }

    async fn find_path(&self, paths: HashSet<Vec<Vertex>>) -> Result<Vec<BalanceQueryResponse>> {
        let mut balance_map = HashMap::new();
        let mut min_pressure = std::i128::MAX;
        for path in paths.into_iter() {
            let balances = self.vertexes_to_balance_list(path).await?;
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
            None => Ok(vec![]),
        }
    }

    async fn vertexes_to_balance_list(
        &self,
        mut vertexes: Vec<Vertex>,
    ) -> Result<Vec<BalanceQueryResponse>> {
        ensure!(vertexes.len() >= 2, "should have at lease 1 hops");
        let mut result = Vec::new();
        let first = vertexes.remove(0).id;
        let second = vertexes.get(0).expect("should have").id;

        ensure!(
            first == self.wallet.account(),
            "first hop should be local address"
        );
        let total_amount = self
            .stats_mgr
            .back_pressure(&(first, second.clone()))
            .await?;

        let response = BalanceQueryResponse::new(
            first,
            second.clone(),
            self.wallet.channel_balance(second.clone()).await?,
            self.wallet
                .participant_channel_balance(second.clone())
                .await?,
            total_amount,
        );
        info!("find first hop balance info {:?}", response);
        result.push(response);

        let length = vertexes.len();
        if length > 1 {
            for (index, _vertex) in vertexes.iter().enumerate() {
                if index <= length - 2 {
                    let local_addr = vertexes.get(index).unwrap().clone();
                    let remote_addr = vertexes.get(index + 1).unwrap().clone();
                    info!(
                        "check hop balance from {} to {}",
                        local_addr.id, remote_addr.id,
                    );
                    let response = self.query_balance(local_addr.id, remote_addr.id).await?;
                    info!(
                        "check hop balance from {} to {},balance is {}",
                        local_addr.id, remote_addr.id, response.local_balance
                    );
                    result.push(response);
                }
            }
        }

        Ok(result)
    }

    async fn handle_stream(inner: Arc<RouterInner>, result: Result<(u64, ChannelChangeEvent)>) {
        match result {
            Ok((u, t)) => {
                info!("get {} from stream,event is {:?}", u, t);
                let result = inner.handle_channel_stream(u, t).await;
                match result {
                    Ok(_t) => {}
                    Err(e) => {
                        warn!("get error from server channel stream, {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("get error from server channel stream, {}", e);
            }
        }
    }

    async fn handle_channel_stream(&self, _number: u64, event: ChannelChangeEvent) -> Result<()> {
        match event {
            ChannelChangeEvent::Opened {
                channel_address,
                balances,
            } => {
                ensure!(balances.len() == 2, "balances len should be 2");
                let edge = generate_edge(channel_address, balances)?;
                let _index = self.graph_store.put_edge(&edge, 0, true)?;
            }
            ChannelChangeEvent::Closed {
                channel_address,
                balances,
            } => {
                ensure!(balances.len() == 2, "balances len should be 2");
                let edge = generate_edge(channel_address, balances)?;
                self.graph_store.remove_edge(&edge)?;
            }
            ChannelChangeEvent::Locked {
                channel_address,
                balances,
            } => {
                ensure!(balances.len() == 2, "balances len should be 2");
                let edge = generate_edge(channel_address, balances)?;
                self.graph_store.remove_edge(&edge)?;
            }
        }
        Ok(())
    }

    async fn handle_balance_query_request(
        &self,
        sender_addr: AccountAddress,
        msg: BalanceQueryRequest,
    ) -> Result<()> {
        info!("off balance query request message");
        if msg.local_addr != self.wallet.account() {
            warn!(
                "balance query local addr is not right,msg.local_addr is {},my addr is {}",
                msg.local_addr,
                self.wallet.account()
            );
            return Ok(());
        }
        let balance = self.wallet.channel_balance(msg.remote_addr).await?;
        let total_amount = self
            .stats_mgr
            .back_pressure(&(msg.local_addr, msg.remote_addr))
            .await?;
        let response = BalanceQueryResponse::new(
            msg.local_addr,
            msg.remote_addr,
            balance,
            self.wallet
                .participant_channel_balance(msg.remote_addr)
                .await?,
            total_amount,
        );
        info!("send message to {}", sender_addr);
        self.network_sender.unbounded_send((
            sender_addr.clone(),
            RouterNetworkMessage::BalanceQueryResponse(response),
        ))?;

        Ok(())
    }

    async fn handle_balance_query_response(
        &self,
        sender_addr: AccountAddress,
        msg: BalanceQueryResponse,
    ) -> Result<()> {
        info!("get response from {}", sender_addr);
        self.message_processor
            .send_response(
                sender_addr.hash(),
                RouterNetworkMessage::BalanceQueryResponse(msg),
            )
            .await?;
        Ok(())
    }

    async fn query_balance(
        &self,
        local_addr: AccountAddress,
        remote_addr: AccountAddress,
    ) -> Result<BalanceQueryResponse> {
        let request = BalanceQueryRequest::new(local_addr.clone(), remote_addr.clone());
        self.network_sender.unbounded_send((
            local_addr.clone(),
            RouterNetworkMessage::BalanceQueryRequest(request),
        ))?;
        let (tx, rx) = futures::channel::mpsc::channel(1);
        let message_future = MessageFuture::new(rx);
        self.message_processor
            .add_future(local_addr.hash(), tx.clone())
            .await;
        let response = message_future.await?;
        match response {
            RouterNetworkMessage::BalanceQueryResponse(data) => Ok(data),
            _ => bail!("can't find balance"),
        }
    }
}

fn generate_edge(
    channel_address: AccountAddress,
    balances: HashMap<AccountAddress, u64>,
) -> Result<Edge> {
    let mut vertexes = Vec::new();
    for (addr, balance) in balances.iter() {
        info!(
            "get channel opened event ,channel addr is {} , addr {} balance is {}",
            channel_address, addr, balance,
        );
        vertexes.push(Vertex::new_with_bi_type(addr.clone()));
    }
    Edge::from_vertexes(vertexes)
}

fn respond_with<T>(responder: futures::channel::oneshot::Sender<T>, msg: T) {
    if let Err(_t) = responder.send(msg) {
        error!("fail to send back response, receiver is dropped",);
    };
}

#[test]
fn router_test() {
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
    let mut router1 = TableRouter::new(
        client.clone(),
        executor.clone(),
        wallet1.clone(),
        rtx1,
        rrx1,
        Arc::new(Stats::new(executor.clone())),
    );
    router1.start().unwrap();

    let (_network2, tx2, rx2, close_tx2) = build_network_service(&network_config2, keypair2);
    let _identify2 = _network2.identify();
    let (rtx2, rrx2) = _prepare_network(tx2, rx2, executor.clone());
    let mut router2 = TableRouter::new(
        client.clone(),
        executor.clone(),
        wallet2.clone(),
        rtx2,
        rrx2,
        Arc::new(Stats::new(executor.clone())),
    );
    router2.start().unwrap();

    let (_network3, tx3, rx3, close_tx3) = build_network_service(&network_config3, keypair3);
    let _identify3 = _network3.identify();
    let (rtx3, rrx3) = _prepare_network(tx3, rx3, executor.clone());
    let mut router3 = TableRouter::new(
        client.clone(),
        executor.clone(),
        wallet3.clone(),
        rtx3,
        rrx3,
        Arc::new(Stats::new(executor.clone())),
    );
    router3.start().unwrap();

    let (_network4, tx4, rx4, close_tx4) = build_network_service(&network_config4, keypair4);
    let _identify4 = _network4.identify();
    let (rtx4, rrx4) = _prepare_network(tx4, rx4, executor.clone());
    let mut router4 = TableRouter::new(
        client.clone(),
        executor.clone(),
        wallet4.clone(),
        rtx4,
        rrx4,
        Arc::new(Stats::new(executor.clone())),
    );
    router4.start().unwrap();

    let (_network5, tx5, rx5, close_tx5) = build_network_service(&network_config5, keypair5);
    let _identify5 = _network5.identify();
    let (rtx5, rrx5) = _prepare_network(tx5, rx5, executor.clone());
    let mut router5 = TableRouter::new(
        client.clone(),
        executor.clone(),
        wallet5.clone(),
        rtx5,
        rrx5,
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
            .find_path_by_addr(addr1.clone(), addr2.clone())
            .await?;

        assert_eq!(path.len(), 1);
        assert_eq!(path.get(0).expect("should have").local_addr, addr1.clone());
        assert_eq!(path.get(0).expect("should have").remote_addr, addr2.clone());

        let path = router1
            .find_path_by_addr(addr1.clone(), addr4.clone())
            .await?;

        assert_eq!(path.len(), 3);
        assert_eq!(path.get(0).expect("should have").local_addr, addr1.clone());
        assert_eq!(path.get(2).expect("should have").remote_addr, addr4.clone());

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
        Wallet::new_with_client(account_address, keypair.clone(), client, store_path.path())
            .unwrap();
    let wallet = wallet.start().await.unwrap();
    wallet.enable_channel().await.unwrap();
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
