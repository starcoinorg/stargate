#![feature(async_await)]

use futures::{
    io::{AsyncReadExt},
    sink::{SinkExt},
    future::{FutureExt},
    compat::{Sink01CompatExt} ,
    prelude::*,
};
use memsocket::{MemorySocket};
use netcore::transport::{memory::MemoryTransport};
use std::io::Result;
use tokio::runtime::{Runtime};
use node::node::Node;
use switch::{switch::Switch};
use tokio::codec::{Framed,LengthDelimitedCodec};
use bytes::Bytes;

#[test]
fn start_server_test() -> Result<()> {
    let mut rt = Runtime::new().unwrap();
    let executor = rt.executor();

    let switch:Switch<MemorySocket> = Switch::new();
    let node = Node::new(switch);

    node.start_server(&executor,MemoryTransport::default(),"/memory/10".parse().unwrap());
        
    let mut dialer=MemorySocket::connect(10).unwrap();
    let mut stream = Framed::new(dialer.compat(), LengthDelimitedCodec::new()).sink_compat();

    let f=async move{
        stream.send(Bytes::from("hello")).await.unwrap();
        let result = stream.next().await;   
        match result {
            Some(Ok(data)) => {assert_eq!(&data[..],b"hello");  },
            Some(Err(_)) => println!("error"),
            None    => println!("Cannot divide by 0"),
        }              
                      
    };
    executor.spawn(f.boxed()
            .unit_error()
            .compat(),);
    //rt.shutdown_on_idle().wait().unwrap();
    Ok(())
}