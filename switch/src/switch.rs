use network::p2p::TTcpSteam;
use crate::link::ChannelLink;
use std::collections::HashMap;
use std::sync::{Mutex,Arc};

pub struct Switch<T:TTcpSteam>{
    lock:Arc<Mutex<u32>>,
    links:HashMap<String,ChannelLink<T>>,
    pending_links:HashMap<String,ChannelLink<T>>,
}

impl<T:TTcpSteam> Switch<T>{
    fn addLink(link:ChannelLink<T>){

    }

    fn addPendingLink(link:ChannelLink<T>){

    }

    fn removeLink(id:String){

    }

    fn sendHtlc(){

    }

    fn forward(){

    }

    fn route(){

    }

    fn sendMessage(){

    }
}