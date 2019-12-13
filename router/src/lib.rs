use anyhow::{ensure, Result};

use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::channel::oneshot;
use futures::stream::StreamExt;
use graphdb::{edge::Edge, graph_store::GraphStore, vertex::Vertex};
use libra_crypto::{test_utils::KeyPair, Uniform};
use libra_logger::prelude::*;
use libra_tools::tempdir::TempPath;
use libra_types::account_address::AccountAddress;
use rand::prelude::*;
use sgchain::star_chain_client::ChainClient;
use sgchain::star_chain_client::{faucet_async_2, MockChainClient};
use sgtypes::system_event::Event;
use sgwallet::wallet::Wallet;
use sgwallet::{get_channel_events, ChannelChangeEvent};
use std::collections::HashMap;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::runtime::Handle;
use tokio::runtime::Runtime;

pub struct Router {
    inner: Option<RouterInner>,
    executor: Handle,
    sender: UnboundedSender<RouterMessage>,
    control_sender: UnboundedSender<Event>,
}

struct RouterInner {
    chain_client: Arc<dyn ChainClient>,
    graph_store: GraphStore,
    receiver: UnboundedReceiver<RouterMessage>,
    control_receiver: UnboundedReceiver<Event>,
}

enum RouterMessage {
    FindPath {
        start: Vertex,
        end: Vertex,
        responder: oneshot::Sender<Result<Option<Vec<Vertex>>>>,
    },
}

impl Router {
    pub fn new(chain_client: Arc<dyn ChainClient>, executor: Handle) -> Self {
        let (sender, receiver) = futures::channel::mpsc::unbounded();
        let (control_sender, control_receiver) = futures::channel::mpsc::unbounded();
        let inner = RouterInner {
            chain_client,
            receiver,
            control_receiver,
            graph_store: GraphStore::new(false, None).unwrap(),
        };
        Self {
            inner: Some(inner),
            executor,
            sender,
            control_sender,
        }
    }

    async fn find_path(&self, start: Vertex, end: Vertex) -> Result<Option<Vec<Vertex>>> {
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

    pub async fn find_path_by_addr(
        &self,
        start: AccountAddress,
        end: AccountAddress,
    ) -> Result<Option<Vec<AccountAddress>>> {
        let start_node = Vertex::new_with_bi_type(start);
        let end_node = Vertex::new_with_bi_type(end);
        let vertexes = self.find_path(start_node, end_node).await?;
        Ok(match vertexes {
            Some(vertex_list) => Some(vertex_list.iter().clone().map(|v| v.id).collect()),
            None => None,
        })
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
}

impl RouterInner {
    async fn start(mut self) {
        let client = self.chain_client.clone();

        let stream = get_channel_events(client, 0, 100).fuse();
        let mut stream = Box::pin(stream);

        loop {
            futures::select! {
                message = stream.select_next_some() => {
                    self.handle_stream(message).await;
                },
                router_message = self.receiver.select_next_some()=>{
                    self.handle_router_msg(router_message).await;
                },
                _ = self.control_receiver.select_next_some() =>{
                    info!("shutdown");
                    break;
                },
            }
        }
    }

    async fn handle_router_msg(&mut self, msg: RouterMessage) {
        match msg {
            RouterMessage::FindPath {
                start,
                end,
                responder,
            } => {
                let result = self.graph_store.find_path(&start, &end);
                respond_with(responder, result);
            }
        }
    }

    async fn handle_stream(&self, result: Result<(u64, ChannelChangeEvent)>) {
        match result {
            Ok((u, t)) => {
                info!("get {} from stream,event is {:?}", u, t);
                let result = self.handle_channel_stream(u, t).await;
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
    use libra_logger::prelude::*;
    use sgchain::star_chain_client::MockChainClient;
    use std::sync::Arc;

    libra_logger::init_for_e2e_testing();
    let mut rt = Runtime::new().unwrap();
    let executor = rt.handle().clone();

    let (mock_chain_service, _handle) = MockChainClient::new();
    let client = Arc::new(mock_chain_service);

    let mut router = Router::new(client.clone(), executor.clone());
    router.start().unwrap();

    let (wallet1, addr1) = _gen_wallet(executor.clone(), client.clone()).unwrap();
    let (wallet2, _addr2) = _gen_wallet(executor.clone(), client.clone()).unwrap();
    let (wallet3, addr3) = _gen_wallet(executor.clone(), client.clone()).unwrap();

    let _wallet1 = wallet1.clone();
    let _wallet2 = wallet2.clone();
    let _wallet3 = wallet3.clone();

    let f = async move {
        _open_channel(wallet1.clone(), wallet2.clone(), 100000, 100000).await?;
        _open_channel(wallet2.clone(), wallet3.clone(), 100000, 100000).await?;

        _delay(Duration::from_millis(5000)).await;

        let result = router.find_path_by_addr(addr1, addr3).await?;
        match result {
            Some(v) => {
                assert_eq!(v.len(), 3);
            }
            None => {
                assert_eq!(0, 1);
            }
        };
        wallet1.stop().await?;
        wallet2.stop().await?;
        wallet3.stop().await?;
        router.shutdown().await?;
        Ok::<_, Error>(())
    };

    rt.block_on(f).unwrap();

    debug!("here");
}

fn _gen_wallet(
    executor: Handle,
    client: Arc<MockChainClient>,
) -> Result<(Arc<Wallet>, AccountAddress)> {
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
    let f = async {
        wallet.enable_channel().await.unwrap();
    };
    rt.block_on(f);

    wallet.start(&executor).unwrap();
    Ok((Arc::new(wallet), account_address))
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
