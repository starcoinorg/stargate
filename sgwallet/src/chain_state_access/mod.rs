// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]
use crate::utils::{ActorHandle, Msg, TypedActor};
use async_trait::async_trait;
use libra_types::account_address::AccountAddress;
use libra_types::transaction::Version;
use sgchain::star_chain_client::ChainClient;
use sgtypes::account_state::AccountState;
use std::collections::HashMap;

use std::sync::Arc;
pub enum Request {}
pub enum Response {}

pub type AccessMsg = Msg<Request, Response>;
pub type ChainStateHandle = ActorHandle<(), AccessMsg>;

pub struct ChainStateAccessor {
    chain_client: Arc<dyn ChainClient>,
    cache: HashMap<AccountAddress, HashMap<Version, AccountState>>,
}
#[async_trait]
impl TypedActor<Request, Response> for ChainStateAccessor {
    async fn handle_call(&mut self, _req: Request) -> Response {
        unimplemented!()
    }

    async fn handle_cast(&mut self, _msg: Request) {
        unimplemented!()
    }
}
