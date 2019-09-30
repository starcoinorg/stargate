use crate::link::ChannelLink;
use futures::io::{AsyncRead, AsyncWrite};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub struct Switch<T: AsyncRead + AsyncWrite + Send> {
    //lock:Arc<Mutex<u32>>,
    links: HashMap<String, ChannelLink<T>>,
    pending_links: HashMap<String, ChannelLink<T>>,
}

impl<T: AsyncRead + AsyncWrite + Send> Switch<T> {
    pub fn new() -> Self {
        Self {
            links: HashMap::new(),
            pending_links: HashMap::new(),
        }
    }

    fn addLink(link: ChannelLink<T>) {}

    fn addPendingLink(link: ChannelLink<T>) {}

    fn removeLink(id: String) {}

    fn sendHtlc() {}

    fn forward() {}

    fn route() {}

    fn sendMessage() {}
}
