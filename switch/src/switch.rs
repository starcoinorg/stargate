use crate::link::ChannelLink;
use std::collections::HashMap;
use std::sync::{Mutex,Arc};
use futures::{
    io::{AsyncRead, AsyncWrite},
};

pub struct Switch<T:AsyncRead+AsyncWrite+Send>{
    lock:Arc<Mutex<u32>>,
    links:HashMap<String,ChannelLink<T>>,
    pending_links:HashMap<String,ChannelLink<T>>,
}

impl<T:AsyncRead+AsyncWrite+Send> Switch<T>{
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