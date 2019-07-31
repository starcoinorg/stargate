extern crate futures;

use futures::{Stream, task::{Context, Poll}};
use std::pin::Pin;

pub struct SgChannel {}

pub struct SgChannelStream {
    sg_chan: SgChannel,
}

impl Stream for SgChannelStream {
    type Item = SgChannel;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        unimplemented!()
    }
}