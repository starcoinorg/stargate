#[cfg(test)]
mod test {
    use async_std::task;
    use consensus::mine_state::{DummyBlockIndex, MineStateManager};
    use consensus::{setup_minerproxy_service, MineClient, MineState};
    use futures::{channel::oneshot, compat::Future01CompatExt};

    #[test]
    pub fn test_miner_service() {
        let mut mine_state = MineStateManager::new(DummyBlockIndex {});
        let mut miner_grpc_srv =
            setup_minerproxy_service(mine_state.clone(), "127.0.0.1:4251".to_string());
        miner_grpc_srv.start();
        for &(ref host, port) in miner_grpc_srv.bind_addrs() {
            println!("Listening on {}:{}", host, port);
        }
        let (tx, rx) = oneshot::channel();
        task::spawn(async move {
            for _i in 0..10 {
                let (rx, _tx) = mine_state.mine_block(vec![0; 32]);
                let _proof = rx.recv().await.unwrap();
                println!("Mined success");
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            let _ = tx.send(());
        });
        task::spawn(async move {
            println!("Start mine client");
            let mine_client = MineClient::new("127.0.0.1:4251".to_string());
            mine_client.start().await;
        });
        task::block_on(async move {
            rx.await.unwrap();
            miner_grpc_srv.shutdown().compat().await.unwrap();
        });
    }
}
