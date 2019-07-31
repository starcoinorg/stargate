extern crate futures;

use futures::{Stream, task::{Context, Poll}};
use std::pin::Pin;
use types::account_address::AccountAddress;

pub struct SgChannel {
    pk_first:AccountAddress,
    pk_second:AccountAddress,
    //Capacity 
}

pub struct SgChannelStream;

impl Stream for SgChannelStream {
    type Item = SgChannel;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        unimplemented!()
    }
}