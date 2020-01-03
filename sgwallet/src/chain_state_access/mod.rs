// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]
use anyhow::{format_err, Result};
use async_trait::async_trait;
use coerce_rt::actor::{
    context::ActorHandlerContext,
    message::{Handler, Message},
    Actor,
};
use futures::channel::oneshot;
use libra_logger::prelude::*;
use libra_types::{access_path::DataPath, account_address::AccountAddress, transaction::Version};
use sgchain::star_chain_client::ChainClient;
use sgtypes::account_state::AccountState;
use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Arc,
};

pub struct AccessState {
    pub version: Option<Version>,
    pub account: AccountAddress,
    pub data_path: DataPath,
}
impl Message for AccessState {
    type Result = oneshot::Receiver<Result<Option<Vec<u8>>>>;
}

pub struct RemoteAccessResult {
    pub account: AccountAddress,
    pub version: Option<Version>,
    pub result: Result<(Version, Option<AccountState>)>,
}

impl Message for RemoteAccessResult {
    type Result = ();
}

pub struct ChainStateAccessor {
    chain_client: Arc<dyn ChainClient>,
    cache: HashMap<AccountAddress, HashMap<Version, Option<AccountState>>>,
    ongoing_requests: HashMap<(AccountAddress, Option<Version>), oneshot::Sender<()>>,
    waiting_list: HashMap<
        (AccountAddress, Option<Version>),
        Vec<(DataPath, oneshot::Sender<Result<Option<Vec<u8>>>>)>,
    >,
}

#[async_trait]
impl Actor for ChainStateAccessor {
    async fn started(&mut self, _ctx: &mut ActorHandlerContext) {
        info!("chain state accessor started");
    }

    async fn stopped(&mut self, _ctx: &mut ActorHandlerContext) {
        info!("chain state accessor stopped");
    }
}

impl ChainStateAccessor {
    pub fn new(chain_client: Arc<dyn ChainClient>) -> Self {
        Self {
            chain_client,
            cache: HashMap::new(),
            ongoing_requests: HashMap::new(),
            waiting_list: HashMap::new(),
        }
    }

    async fn remote_access(
        chain_client: Arc<dyn ChainClient>,
        account_address: AccountAddress,
        version: Option<Version>,
        _cancel_rx: oneshot::Receiver<()>,
    ) -> Result<(Version, Option<AccountState>)> {
        let result = tokio::task::block_in_place(|| {
            chain_client.get_account_state_with_proof(&account_address, version)
        })?;
        let (version, state, proof) = result;
        match state {
            Some(s) => {
                let account_state = AccountState::from_account_state_blob(version, s, proof)?;
                Ok((version, Some(account_state)))
            }
            None => Ok((version, None)),
        }
    }

    fn add_to_waiting_list(
        &mut self,
        key: (AccountAddress, Option<Version>),
        data_path: DataPath,
        tx: oneshot::Sender<Result<Option<Vec<u8>>>>,
    ) {
        match self.waiting_list.entry(key) {
            Entry::Occupied(mut o) => {
                o.get_mut().push((data_path, tx));
            }
            Entry::Vacant(v) => {
                v.insert(vec![(data_path, tx)]);
            }
        }
    }

    fn add_to_cache(
        &mut self,
        account: AccountAddress,
        version: Version,
        state: Option<AccountState>,
    ) {
        match self.cache.entry(account) {
            Entry::Occupied(mut o) => {
                o.get_mut().insert(version, state);
            }
            Entry::Vacant(v) => {
                let mut new_map = HashMap::new();
                new_map.insert(version, state);
                v.insert(new_map);
            }
        }
    }

    fn get_from_cache(
        &self,
        account: AccountAddress,
        version: Version,
        data_path: &DataPath,
    ) -> Option<Option<Vec<u8>>> {
        match self.cache.get(&account).and_then(|d| d.get(&version)) {
            None => None,
            Some(s) => Some(s.as_ref().and_then(|t| t.get_state(data_path))),
        }
    }
}

#[async_trait]
impl Handler<AccessState> for ChainStateAccessor {
    async fn handle(
        &mut self,
        message: AccessState,
        ctx: &mut ActorHandlerContext,
    ) -> <AccessState as Message>::Result {
        let AccessState {
            version,
            account,
            data_path,
        } = message;
        let blob = match version {
            Some(v) => self.get_from_cache(account, v, &data_path),
            None => None,
        };

        let (tx, rx) = oneshot::channel();
        match blob {
            Some(t) => {
                tx.send(Ok(t)).expect("should be ok");
            }
            None => {
                let key = (account, version);
                if self.ongoing_requests.contains_key(&key) {
                    self.add_to_waiting_list(key, data_path, tx);
                } else {
                    let (cancel_tx, cancel_rx) = oneshot::channel();
                    let my_actor_id = ctx.actor_id().clone();
                    let mut myself = ctx
                        .actor_context_mut()
                        .get_actor::<Self>(my_actor_id.clone())
                        .await
                        .unwrap();
                    let remote_accessing = ChainStateAccessor::remote_access(
                        self.chain_client.clone(),
                        account,
                        version,
                        cancel_rx,
                    );
                    tokio::spawn(async move {
                        let result = remote_accessing.await;
                        let result = RemoteAccessResult {
                            account,
                            version,
                            result,
                        };
                        if let Err(_e) = myself.send(result).await {
                            error!("actor {} is already stoppped", my_actor_id);
                        }
                    });
                    self.ongoing_requests.insert((account, version), cancel_tx);
                    self.add_to_waiting_list(key, data_path, tx);
                }
            }
        }

        rx
    }
}

#[async_trait]
impl Handler<RemoteAccessResult> for ChainStateAccessor {
    async fn handle(
        &mut self,
        message: RemoteAccessResult,
        _ctx: &mut ActorHandlerContext,
    ) -> <RemoteAccessResult as Message>::Result {
        let RemoteAccessResult {
            account,
            version,
            result,
        } = message;
        self.ongoing_requests.remove(&(account, version));
        let waitings = self.waiting_list.remove(&(account, version));

        let cached_version = match result {
            Ok((version, state)) => {
                self.add_to_cache(account, version, state);

                Ok(version)
            }
            Err(e) => Err(e),
        };

        match waitings {
            None => {
                warn!(
                    "no one is waiting for the state of {:?}",
                    (account, version)
                );
            }
            Some(waitings) => {
                for (data_path, sender) in waitings {
                    let to_send = match &cached_version {
                        Ok(v) => {
                            let s = self
                                .get_from_cache(account, *v, &data_path)
                                .expect("cache should contain this");
                            Ok(s)
                        }
                        Err(_e) => Err(format_err!("fail to get remote data")),
                    };
                    if let Err(_) = sender.send(to_send) {
                        warn!("receiver is already dropped");
                    }
                }
            }
        }
    }
}
