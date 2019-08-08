extern crate grpcio;

use grpcio::ClientSStreamReceiver;
use star_types::proto::chain::WatchTransactionResponse;
use futures::{Stream, Poll, Async};
use types::transaction::SignedTransaction;
use proto_conv::FromProto;

pub struct WatchTransactionStream {
    receive: ClientSStreamReceiver<WatchTransactionResponse>,
}

impl WatchTransactionStream {
    pub fn new(receive: ClientSStreamReceiver<WatchTransactionResponse>) -> Self {
        WatchTransactionStream { receive }
    }
}

impl Stream for WatchTransactionStream {
    type Item = SignedTransaction;
    type Error = Box<grpcio::Error>;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let resp = self.receive.poll().map_err(|e| {
            Box::new(e)
        }).map(|tmp| {
            match tmp {
                Async::Ready(tmp_option) => {
                    match tmp_option {
                        Some(wtr) => {
                            Async::Ready(Some(SignedTransaction::from_proto((*wtr.get_signed_txn()).clone()).unwrap()))
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