#[cfg(test)]
mod test {
    use async_std::task;
    use consensus::mine_state::{DummyBlockIndex, MineStateManager};

    use consensus::{setup_minerproxy_service, MineClient, MineState, MinerConfig};
    use futures::{channel::oneshot, compat::Future01CompatExt};
    use libra_logger::prelude::*;

    #[test]
    pub fn test_miner_service() {
        ::libra_logger::init_for_e2e_testing();
        let mut block_index = DummyBlockIndex::new();
        let mut mine_state = MineStateManager::new(block_index.clone());
        let mut miner_grpc_srv =
            setup_minerproxy_service(mine_state.clone(), "127.0.0.1:4251".to_string());
        miner_grpc_srv.start();
        for &(ref host, port) in miner_grpc_srv.bind_addrs() {
            debug!("Listening on {}:{}", host, port);
        }
        let (tx, rx) = oneshot::channel();
        task::spawn(async move {
            for i in 0..12 {
                let (rx, _tx) = mine_state.mine_block(vec![i; 32]);
                let proof = rx.recv().await.unwrap().expect("proof is none.");
                let target = proof.target;
                let algo = proof.algo;
                debug!("Mined success");
                block_index.add_block(target, algo);
                block_index.reset_iter();
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            let _ = tx.send(());
        });
        task::spawn(async move {
            debug!("Start mine client");
            let miner_config = MinerConfig::default();
            let mine_client = MineClient::new(miner_config);
            mine_client.start().await;
        });
        task::block_on(async move {
            rx.await.unwrap();
            miner_grpc_srv.shutdown().compat().await.unwrap();
        });
    }
}
