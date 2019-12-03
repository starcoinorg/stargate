use async_trait::async_trait;
use backoff::backoff::Backoff;
use backoff::ExponentialBackoff;
use failure::prelude::*;
use futures::task::Context;
use futures::{FutureExt, Poll, Stream};
use futures_timer::Delay;
use libra_logger::prelude::*;
use libra_types::access_path::AccessPath;
use libra_types::contract_event::ContractEvent;
use libra_types::{
    get_with_proof::RequestItem, proto::types::UpdateToLatestLedgerRequest, transaction::Version,
};
use sgchain::star_chain_client::ChainClient;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

//pub fn get_event_watcher(
//    chain_client: Arc<dyn ChainClient>,
//    start_number: u64,
//    limit: u64,
//) -> impl Stream<Item = Result<(u64, ContractEvent)>> {
//    unimplemented!()
//    //    EventStream::new(
//    //        chain_client,
//    //        AccessPath::new_for_channel_global_event(),
//    //        start_number,
//    //        limit,
//    //    )
//}

#[async_trait]
pub trait EventQuerier {
    async fn query_events(
        &self,
        access_path: AccessPath,
        start_number: u64,
        limit: u64,
    ) -> Result<BTreeMap<u64, ContractEvent>>;
}

pub struct EventStream {
    evt_access_path: AccessPath,
    start_number: u64,
    limit: u64,

    event_querier: Arc<dyn EventQuerier>,
    cache: BTreeMap<u64, ContractEvent>,
    delay: Option<Delay>,
    backoff: ExponentialBackoff,
}

impl EventStream {
    pub fn new(
        event_querier: Arc<dyn EventQuerier>,
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
    type Item = Result<(u64, ContractEvent)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let s = self.get_mut();
        match s.cache.remove(&s.start_number) {
            Some(v) => {
                s.start_number = s.start_number + 1;
                Poll::Ready(Some(Ok((s.start_number - 1, v))))
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
                                    Poll::Ready(Some(Ok((s.start_number - 1, v))))
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

#[async_trait]
impl<T: ChainClient> EventQuerier for T {
    async fn query_events(
        &self,
        access_path: AccessPath,
        start_number: u64,
        limit: u64,
    ) -> Result<BTreeMap<u64, ContractEvent>> {
        let ri = RequestItem::GetEventsByEventAccessPath {
            access_path,
            start_event_seq_num: start_number,
            ascending: true,
            limit,
        };
        let mut resp = self.update_to_latest_ledger(&build_request(ri, None))?;

        let resp: libra_types::get_with_proof::ResponseItem =
            resp.response_items.remove(0).try_into()?;
        let (events, _) = resp.into_get_events_by_access_path_response()?;
        let mut res = BTreeMap::new();
        for evt in events.into_iter() {
            let num = evt.event_index;
            res.insert(num, evt.event);
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
    use async_trait::async_trait;
    use failure::prelude::*;
    use futures::TryStreamExt;
    use futures_timer::Delay;
    use libra_logger::prelude::*;
    use libra_types::access_path::AccessPath;
    use libra_types::contract_event::ContractEvent;
    use libra_types::event::{EventKey, EVENT_KEY_LENGTH};
    use libra_types::language_storage::TypeTag;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[derive(Debug)]
    struct TestEventQuerier {
        pub fake_none: AtomicU64,
        pub fake_err: AtomicU64,
    }
    #[async_trait]
    impl super::EventQuerier for TestEventQuerier {
        async fn query_events(
            &self,
            _access_path: AccessPath,
            start_number: u64,
            _limit: u64,
        ) -> Result<BTreeMap<u64, ContractEvent>> {
            if start_number == 0 {
                let mut test_cases = BTreeMap::new();
                test_cases.insert(
                    0,
                    ContractEvent::new(
                        EventKey::new([0; EVENT_KEY_LENGTH]),
                        0,
                        TypeTag::Bool,
                        vec![],
                    ),
                );
                test_cases.insert(
                    1,
                    ContractEvent::new(
                        EventKey::new([0; EVENT_KEY_LENGTH]),
                        1,
                        TypeTag::Bool,
                        vec![],
                    ),
                );
                return Ok(test_cases);
            }
            if start_number == 2 {
                let left_time = self.fake_err.load(Ordering::Relaxed);
                if left_time > 0 {
                    self.fake_err.store(left_time - 1, Ordering::Relaxed);
                    bail!("fake error")
                }

                let mut test_cases = BTreeMap::new();
                test_cases.insert(
                    2,
                    ContractEvent::new(
                        EventKey::new([0; EVENT_KEY_LENGTH]),
                        2,
                        TypeTag::Bool,
                        vec![],
                    ),
                );
                test_cases.insert(
                    3,
                    ContractEvent::new(
                        EventKey::new([0; EVENT_KEY_LENGTH]),
                        3,
                        TypeTag::Bool,
                        vec![],
                    ),
                );
                return Ok(test_cases);
            }
            if start_number == 4 {
                let left_time = self.fake_none.load(Ordering::Relaxed);
                if left_time > 0 {
                    self.fake_none.store(left_time - 1, Ordering::Relaxed);
                    return Ok(BTreeMap::new());
                }

                let mut test_cases = BTreeMap::new();
                test_cases.insert(
                    4,
                    ContractEvent::new(
                        EventKey::new([0; EVENT_KEY_LENGTH]),
                        4,
                        TypeTag::Bool,
                        vec![],
                    ),
                );
                test_cases.insert(
                    5,
                    ContractEvent::new(
                        EventKey::new([0; EVENT_KEY_LENGTH]),
                        5,
                        TypeTag::Bool,
                        vec![],
                    ),
                );
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
                    Arc::new(q),
                    AccessPath::new_for_channel_global_event(),
                    0,
                    1000,
                );
                for i in 0u64..5 {
                    match s.try_next().await {
                        Ok(Some((idx, _))) => assert_eq!(i, idx),
                        _ => panic!("fail in i: {}", i),
                    }
                }
            }
        });
    }
}
