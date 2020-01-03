// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]

use sgchain::star_chain_client::{ChainClient, MockChainClient};
use std::sync::Arc;

pub fn run_with_mock_client<F, T>(mut f: F) -> T
where
    F: FnMut(Arc<dyn ChainClient>) -> T,
{
    libra_logger::try_init_for_testing();
    let _ = slog_stdlog::init();
    let (mock_chain_service, _handle) = MockChainClient::new();
    //    std::thread::sleep(Duration::from_millis(1500));
    let chain_client = Arc::new(mock_chain_service);
    f(chain_client.clone())
}
