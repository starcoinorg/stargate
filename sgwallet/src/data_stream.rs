// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
use anyhow::{bail, Result};
use async_trait::async_trait;
use backoff::backoff::Backoff;
use backoff::ExponentialBackoff;
use futures::task::Context;
use futures::task::Poll;
use futures::{FutureExt, Stream};
use futures_timer::Delay;
use libra_logger::prelude::*;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

#[async_trait]
pub trait DataQuery: Send + Sync {
    type Item;
    async fn query(&self, version: u64, limit: u64) -> Result<BTreeMap<u64, Self::Item>>;
}

pub struct DataStream<T> {
    start_number: u64,
    limit: u64,
    data_query: Box<dyn DataQuery<Item = T>>,
    delay: Option<Delay>,
    backoff: ExponentialBackoff,
    cache: BTreeMap<u64, T>,
}

impl<T> DataStream<T> {
    pub fn new(data_query: Box<dyn DataQuery<Item = T>>, start_version: u64, limit: u64) -> Self {
        DataStream {
            start_number: start_version,
            limit,
            data_query,
            delay: None,
            backoff: ExponentialBackoff::default(),
            cache: BTreeMap::new(),
        }
    }
}

impl<T> DataStream<T> {
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

impl<T: Unpin> Stream for DataStream<T> {
    type Item = Result<T>;

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

                let event_query = s.data_query.query(s.start_number, s.limit).poll_unpin(cx);

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
