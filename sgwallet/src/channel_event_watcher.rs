use anyhow::{bail, Result};
use async_trait::async_trait;
use backoff::backoff::Backoff;
use backoff::ExponentialBackoff;
use futures::task::Context;
use futures::{FutureExt, Poll, Stream, TryStreamExt};
use futures_timer::Delay;
use libra_logger::prelude::*;
use libra_types::access_path::{AccessPath, DataPath};
use libra_types::account_address::AccountAddress;
use libra_types::channel::{
    channel_event_struct_tag, channel_struct_tag, ChannelEvent, ChannelResource,
};
use libra_types::contract_event::{ContractEvent, EventWithProof};
use libra_types::language_storage::TypeTag;
use libra_types::{
    get_with_proof::RequestItem, proto::types::UpdateToLatestLedgerRequest, transaction::Version,
};
use sgchain::star_chain_client::ChainClient;
use std::collections::{BTreeMap, HashMap};
use std::convert::{TryFrom, TryInto};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub enum ChannelChangeEvent {
    Opened {
        channel_address: AccountAddress,
        balances: HashMap<AccountAddress, u64>,
    },
    Locked {
        channel_address: AccountAddress,
        balances: HashMap<AccountAddress, u64>,
    },
    Closed {
        channel_address: AccountAddress,
        balances: HashMap<AccountAddress, u64>,
    },
}

pub fn get_channel_events(
    chain_client: Arc<dyn ChainClient>,
    start_number: u64,
    limit: u64,
) -> impl Stream<Item = Result<(u64, ChannelChangeEvent)>> {
    let chain_client_clone = chain_client.clone();
    EventStream::new(
        Box::new(ChainClientEventQuerier(chain_client.clone())),
        AccessPath::new_for_channel_global_event(),
        start_number,
        limit,
    )
    .and_then(move |event_with_proof| {
        get_channel_change(chain_client_clone.clone(), event_with_proof)
    })
}

async fn get_channel_change(
    chain_client: Arc<dyn ChainClient>,
    evt_with_proof: EventWithProof,
) -> Result<(u64, ChannelChangeEvent)> {
    let channel_event = parse_channel_event(&evt_with_proof.event)?;
    let version = evt_with_proof.transaction_version;
    let state = ChainClientEventQuerier(chain_client)
        .get_account_state(channel_event.channel_address(), Some(version))
        .await?;
    match state {
        None => bail!("channel state should exists"),
        Some(mut s) => {
            let path = DataPath::onchain_resource_path(channel_struct_tag()).to_vec();
            let addresses = match s.remove(&path) {
                None => bail!("channel resource should exists"),
                Some(value) => ChannelResource::make_from(value)?.participants().to_vec(),
            };
            let balances = addresses
                .into_iter()
                .zip(channel_event.balances().to_vec().into_iter())
                .collect::<HashMap<AccountAddress, u64>>();
            let e = match channel_event.stage() {
                0 => ChannelChangeEvent::Opened {
                    channel_address: channel_event.channel_address(),
                    balances,
                },
                1 => ChannelChangeEvent::Locked {
                    channel_address: channel_event.channel_address(),
                    balances,
                },
                2 => ChannelChangeEvent::Closed {
                    channel_address: channel_event.channel_address(),
                    balances,
                },
                _ => unreachable!(),
            };
            Ok((evt_with_proof.event.sequence_number(), e))
        }
    }
}

fn parse_channel_event(event: &ContractEvent) -> Result<ChannelEvent> {
    match event.type_tag() {
        TypeTag::Struct(s) => {
            debug_assert_eq!(&channel_event_struct_tag(), s);
        }
        t => bail!("channel event type should not be {:#?}", &t),
    }
    let channel_event = ChannelEvent::make_from(event.event_data())?;
    Ok(channel_event)
}

#[async_trait]
pub trait EventQuerier {
    async fn query_events(
        &self,
        access_path: AccessPath,
        start_number: u64,
        limit: u64,
    ) -> Result<BTreeMap<u64, EventWithProof>>;
}

pub struct EventStream {
    evt_access_path: AccessPath,
    start_number: u64,
    limit: u64,

    event_querier: Box<dyn EventQuerier>,
    cache: BTreeMap<u64, EventWithProof>,
    delay: Option<Delay>,
    backoff: ExponentialBackoff,
}

impl EventStream {
    pub fn new(
        event_querier: Box<dyn EventQuerier>,
        evt_access_path: AccessPath,
        start_number: u64,
        limit: u64,
    ) -> Self {
        Self {
            evt_access_path,
            start_number,
            limit,
            event_querier,
            cache: BTreeMap::new(),
            delay: None,
            backoff: ExponentialBackoff::default(),
        }
    }

    fn try_backoff(&mut self, cx: &mut Context<'_>) -> Result<()> {
        match self.backoff.next_backoff() {
            Some(next_backoff) => {
                drop(self.delay.take());
                debug!("next_backoff: {:?}", &next_backoff);
                let mut delay = Delay::new(next_backoff);
                match Pin::new(&mut delay).poll(cx) {
                    Poll::Ready(_) => unreachable!(),
                    Poll::Pending => {}
                }
                self.delay = Some(delay);
                Ok(())
            }
            // FIXME: should err
            None => bail!("backoff timout"),
        }
    }
}

impl Stream for EventStream {
    type Item = Result<EventWithProof>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let s = self.get_mut();
        match s.cache.remove(&s.start_number) {
            Some(v) => {
                s.start_number = s.start_number + 1;
                Poll::Ready(Some(Ok(v)))
            }
            None => {
                if let Some(delay) = s.delay.as_mut() {
                    match Pin::new(delay).poll(cx) {
                        Poll::Ready(_) => {}
                        Poll::Pending => return Poll::Pending,
                    }
                }
                debug_assert!(s.cache.is_empty());

                let event_query = s
                    .event_querier
                    .query_events(s.evt_access_path.clone(), s.start_number, s.limit)
                    .poll_unpin(cx);

                match event_query {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Ok(data)) => {
                        s.backoff.reset();
                        if !data.is_empty() {
                            s.cache = data;
                            match s.cache.remove(&s.start_number) {
                                Some(v) => {
                                    s.start_number = s.start_number + 1;
                                    Poll::Ready(Some(Ok(v)))
                                }
                                None => unreachable!(),
                            }
                        } else {
                            match s.try_backoff(cx) {
                                Err(e) => Poll::Ready(Some(Err(e))),
                                Ok(_) => Poll::Pending,
                            }
                        }
                    }
                    Poll::Ready(Err(_e)) => match s.try_backoff(cx) {
                        Err(e) => Poll::Ready(Some(Err(e))),
                        Ok(_) => Poll::Pending,
                    },
                }
            }
        }
    }
}

struct ChainClientEventQuerier(Arc<dyn ChainClient>);

impl ChainClientEventQuerier {
    /// FIXME: change ChainClient's method into async version.
    async fn get_account_state(
        &self,
        addr: AccountAddress,
        version: Option<u64>,
    ) -> Result<Option<BTreeMap<Vec<u8>, Vec<u8>>>> {
        let ri = RequestItem::GetAccountState { address: addr };
        let mut resp = self
            .0
            .update_to_latest_ledger(&build_request(ri, version))?;
        let resp: libra_types::get_with_proof::ResponseItem =
            resp.response_items.remove(0).try_into()?;
        let s = resp.into_get_account_state_response()?;
        match s.blob {
            Some(b) => Ok(Some(TryFrom::try_from(&b)?)),
            None => Ok(None),
        }
    }
}

#[async_trait]
impl EventQuerier for ChainClientEventQuerier {
    async fn query_events(
        &self,
        access_path: AccessPath,
        start_number: u64,
        limit: u64,
    ) -> Result<BTreeMap<u64, EventWithProof>> {
        let ri = RequestItem::GetEventsByEventAccessPath {
            access_path,
            start_event_seq_num: start_number,
            ascending: true,
            limit,
        };
        let mut resp = self.0.update_to_latest_ledger(&build_request(ri, None))?;

        let resp: libra_types::get_with_proof::ResponseItem =
            resp.response_items.remove(0).try_into()?;
        let (events, _) = resp.into_get_events_by_access_path_response()?;
        let mut res = BTreeMap::new();
        for evt in events.into_iter() {
            res.insert(evt.event.sequence_number(), evt);
        }
        Ok(res)
    }
}

fn build_request(req: RequestItem, ver: Option<Version>) -> UpdateToLatestLedgerRequest {
    libra_types::get_with_proof::UpdateToLatestLedgerRequest::new(ver.unwrap_or(0), vec![req])
        .into()
}

#[cfg(test)]
mod test {
    use crate::channel_event_watcher::EventStream;
    use anyhow::Result;
    use async_trait::async_trait;
    use futures::TryStreamExt;
    use futures_timer::Delay;
    use libra_crypto::HashValue;
    use libra_logger::prelude::*;
    use libra_types::access_path::AccessPath;
    use libra_types::contract_event::{ContractEvent, EventWithProof};
    use libra_types::event::{EventKey, EVENT_KEY_LENGTH};
    use libra_types::language_storage::TypeTag;
    use libra_types::proof::{EventAccumulatorProof, EventProof, TransactionAccumulatorProof};
    use libra_types::transaction::TransactionInfo;
    use libra_types::vm_error::StatusCode;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    #[derive(Debug)]
    struct TestEventQuerier {
        pub fake_none: AtomicU64,
        pub fake_err: AtomicU64,
    }
    fn gen_event_with_proof(i: u64) -> EventWithProof {
        let e = ContractEvent::new(
            EventKey::new([0; EVENT_KEY_LENGTH]),
            i,
            TypeTag::Bool,
            vec![],
        );
        let proof = EventProof::new(
            TransactionAccumulatorProof::new(vec![]),
            TransactionInfo::new(
                HashValue::default(),
                HashValue::default(),
                HashValue::default(),
                0,
                StatusCode::EXECUTED,
            ),
            EventAccumulatorProof::new(vec![]),
        );
        EventWithProof::new(100, i, e, proof)
    }
    #[async_trait]
    impl super::EventQuerier for TestEventQuerier {
        async fn query_events(
            &self,
            _access_path: AccessPath,
            start_number: u64,
            _limit: u64,
        ) -> Result<BTreeMap<u64, EventWithProof>> {
            if start_number == 0 {
                let mut test_cases = BTreeMap::new();
                test_cases.insert(0, gen_event_with_proof(0));
                test_cases.insert(1, gen_event_with_proof(1));
                return Ok(test_cases);
            }
            if start_number == 2 {
                let left_time = self.fake_err.load(Ordering::Relaxed);
                if left_time > 0 {
                    self.fake_err.store(left_time - 1, Ordering::Relaxed);
                    bail!("fake error")
                }

                let mut test_cases = BTreeMap::new();
                test_cases.insert(2, gen_event_with_proof(2));
                test_cases.insert(3, gen_event_with_proof(3));
                return Ok(test_cases);
            }
            if start_number == 4 {
                let left_time = self.fake_none.load(Ordering::Relaxed);
                if left_time > 0 {
                    self.fake_none.store(left_time - 1, Ordering::Relaxed);
                    return Ok(BTreeMap::new());
                }

                let mut test_cases = BTreeMap::new();
                test_cases.insert(4, gen_event_with_proof(4));
                test_cases.insert(5, gen_event_with_proof(5));
                return Ok(test_cases);
            }
            if start_number == 6 {
                return Ok(BTreeMap::new());
            }
            unreachable!()
        }
    }

    #[test]
    fn test_delay() {
        futures::executor::block_on(async move {
            Delay::new(Duration::from_secs(1)).await;
        });
    }

    #[test]
    fn test_event_stream() {
        futures::executor::block_on(async move {
            let qs = vec![
                TestEventQuerier {
                    fake_err: AtomicU64::new(0),
                    fake_none: AtomicU64::new(0),
                },
                TestEventQuerier {
                    fake_err: AtomicU64::new(1),
                    fake_none: AtomicU64::new(0),
                },
                TestEventQuerier {
                    fake_err: AtomicU64::new(0),
                    fake_none: AtomicU64::new(1),
                },
                TestEventQuerier {
                    fake_err: AtomicU64::new(0),
                    fake_none: AtomicU64::new(1),
                },
            ];
            for q in qs.into_iter() {
                info!("test on {:#?}", &q);
                let mut s = EventStream::new(
                    Box::new(q),
                    AccessPath::new_for_channel_global_event(),
                    0,
                    1000,
                );
                for i in 0u64..5 {
                    match s.try_next().await {
                        Ok(Some(v)) => assert_eq!(i, v.event.sequence_number()),
                        _ => panic!("fail in i: {}", i),
                    }
                }
            }
        });
    }
}
