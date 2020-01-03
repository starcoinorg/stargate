// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]
use coerce_rt::actor::{
    message::{Handler, Message},
    Actor, ActorRef,
};
use log::trace;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub trait TimerTick: Message<Result = ()> {}

impl<T> TimerTick for T where T: Message<Result = ()> {}

pub struct Timer {
    stop: tokio::sync::oneshot::Sender<bool>,
}

impl Timer {
    pub fn start<A: Actor, T>(actor: ActorRef<A>, tick: Duration, msg: T) -> Timer
    where
        A: 'static + Handler<T> + Sync + Send,
        T: 'static + Clone + Sync + Send + TimerTick,
    {
        let (stop, stop_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(timer_loop(tick, msg, actor, stop_rx));

        Timer { stop }
    }

    pub fn stop(self) -> bool {
        if let Ok(()) = self.stop.send(true) {
            true
        } else {
            false
        }
    }
}

async fn timer_loop<A: Actor, T>(
    tick: Duration,
    msg: T,
    mut actor: ActorRef<A>,
    mut stop_rx: tokio::sync::oneshot::Receiver<bool>,
) where
    A: 'static + Handler<T> + Sync + Send,
    T: 'static + Clone + Sync + Send + TimerTick,
{
    let mut interval = tokio::time::interval_at(tokio::time::Instant::now(), tick);
    let timer_id = Uuid::new_v4();

    interval.tick().await;

    trace!(target: "Timer", "{} - timer starting", &timer_id);

    loop {
        if stop_rx.try_recv().is_ok() {
            break;
        }

        trace!(target: "Timer", "{} - timer tick", &timer_id);

        let now = Instant::now();
        if let Err(_) = actor.send(msg.clone()).await {
            trace!(target: "Timer", "{} - actor {} is gone", &timer_id, &actor.id);
            break;
        }
        trace!(target: "Timer", "{} - tick res received in {}ms", &timer_id, now.elapsed().as_millis());
        interval.tick().await;
    }

    trace!(target: "Timer", "{} - timer finished", timer_id);
}
