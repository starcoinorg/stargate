extern crate futures;

use futures::{Stream, task::{Context, Poll}};
use std::pin::Pin;
use types::account_address::AccountAddress;

pub struct SgChannelInfo {
    addr_first: AccountAddress,
    addr_second: AccountAddress,
    //Capacity 
}

pub struct SgChannelState {}

pub struct SgChannelStream;

impl Stream for SgChannelStream {
    type Item = SgChannelInfo;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        unimplemented!()
    }
}