use crate::data_stream::{DataQuery, DataStream};
use anyhow::{bail, Result};
use async_trait::async_trait;
use futures::{Stream, TryStreamExt};
use libra_types::{
    access_path::{AccessPath, DataPath},
    account_address::AccountAddress,
    channel::{channel_event_struct_tag, channel_struct_tag, ChannelEvent, ChannelResource},
    contract_event::{ContractEvent, EventWithProof},
    get_with_proof::RequestItem,
    language_storage::TypeTag,
    proto::types::UpdateToLatestLedgerRequest,
    transaction::Version,
};
use sgchain::star_chain_client::ChainClient;
use std::{
    collections::{BTreeMap, HashMap},
    convert::{TryFrom, TryInto},
    sync::Arc,
};

#[derive(Clone, Debug)]
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
    EventStream::new_from_chain_client(chain_client.clone(), start_number, limit).and_then(
        move |event_with_proof| get_channel_change(chain_client_clone.clone(), event_with_proof),
    )
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

type EventStream = DataStream<ChainClientEventQuerier, EventWithProof>;
impl EventStream {
    pub fn new_from_chain_client(
        chain_client: Arc<dyn ChainClient>,
        start_number: u64,
        limit: u64,
    ) -> Self {
        DataStream::new(ChainClientEventQuerier(chain_client), start_number, limit)
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
        let client = self.0.clone();
        let mut resp = tokio::task::block_in_place(move || {
            client.update_to_latest_ledger(&build_request(ri, version))
        })?;
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
impl DataQuery for ChainClientEventQuerier {
    type Item = EventWithProof;

    async fn query(&self, version: u64, limit: u64) -> Result<BTreeMap<u64, Self::Item>> {
        let ri = RequestItem::GetEventsByEventAccessPath {
            access_path: AccessPath::new_for_channel_global_event(),
            start_event_seq_num: version,
            ascending: true,
            limit,
        };
        let client = self.0.clone();
        let mut resp = tokio::task::block_in_place(move || {
            client.update_to_latest_ledger(&build_request(ri, None))
        })?;

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

    use anyhow::{bail, Result};
    use async_trait::async_trait;
    use futures::TryStreamExt;
    use futures_timer::Delay;
    use libra_crypto::HashValue;
    use libra_logger::prelude::*;

    use crate::data_stream::DataStream;
    use libra_types::{
        contract_event::{ContractEvent, EventWithProof},
        event::{EventKey, EVENT_KEY_LENGTH},
        language_storage::TypeTag,
        proof::{EventAccumulatorProof, EventProof, TransactionAccumulatorProof},
        transaction::TransactionInfo,
        vm_error::StatusCode,
    };
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

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
    impl super::DataQuery for TestEventQuerier {
        type Item = EventWithProof;

        async fn query(
            &self,
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
                let mut s = DataStream::new(q, 0, 1000);
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
