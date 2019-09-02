extern crate grpcio;

use grpcio::Error;
use star_types::{proto::chain::WatchData, watch_tx_data::WatchTxData};
use futures::{Stream, Poll, Async};
use types::transaction::SignedTransaction;
use proto_conv::FromProto;
use types::contract_event::ContractEvent;

pub struct WatchStream<S>
    where S: Stream<Item=WatchData, Error=Error> {
    receive: S,
}

impl<S> WatchStream<S>
    where S: Stream<Item=WatchData, Error=Error> {
    pub fn new(receive: S) -> Self {
        WatchStream { receive }
    }
}

impl<S> Stream for WatchStream<S>
    where S: Stream<Item=WatchData, Error=Error> {
    type Item = WatchResp;
    type Error = Box<grpcio::Error>;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let resp = self.receive.poll().map_err(|e| {
            Box::new(e)
        }).map(|tmp| {
            match tmp {
                Async::Ready(tmp_option) => {
                    match tmp_option {
                        Some(data) => {
                            if data.has_event() {
                                Async::Ready(Some(WatchResp::EVENT(ContractEvent::from_proto(data.get_event().clone()).unwrap())))
                            } else {
                                Async::Ready(Some(WatchResp::TX(WatchTxData::from_proto(data.get_tx().clone()).unwrap())))
                            }
                        }
                        None => {
                            Async::Ready(None)
                        }
                    }
                }
                Async::NotReady => Async::NotReady,
            }
        });

        return resp;
    }
}

pub enum WatchResp {
    EVENT(ContractEvent),
    TX(WatchTxData),
}
