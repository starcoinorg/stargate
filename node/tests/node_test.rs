use futures::{
    executor::block_on,
    io::{AsyncReadExt, AsyncWriteExt},
    stream::StreamExt,
};
use memsocket::{MemoryListener, MemorySocket};
use netcore::transport::{Transport,memory::MemoryTransport};
use std::io::Result;
use tokio::runtime::{Runtime,TaskExecutor};
//use node::node::start_server;

#[test]
fn start_server_test() -> Result<()> {
    let mut rt = Runtime::new().unwrap();
    let executor = rt.executor();

    //start_server(&executor,MemoryTransport::default(),"/memory/0".parse().unwrap());

    //rt.shutdown_on_idle().wait().unwrap();
    Ok(())
}