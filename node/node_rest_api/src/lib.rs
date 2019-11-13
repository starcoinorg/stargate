// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate serde_json;

use futures01::{Future, Stream};
use hyper::{
    service::{NewService, Service},
    Body, Error, Request, Response, Server, StatusCode,
};
use libra_logger::prelude::*;
use libra_types::{account_address::AccountAddress, transaction::parse_as_transaction_argument};
use node_internal::node::Node as Node_Internal;
use serde_json::Value;
use sg_config::config::RestConfig;

use sgtypes::signed_channel_transaction::SignedChannelTransaction;
use std::{sync::Arc, thread};

pub fn setup_node_rest(
    config: RestConfig,
    node: Arc<Node_Internal>,
) -> Result<(), Box<dyn std::error::Error>> {
    thread::spawn(move || {
        let web_server = WebServer { node };
        web_server.start(config.address.clone(), config.port);
    });
    Ok(())
}

struct ResponseResult {
    state: bool,
    channel_sequence_number: u64,
    reason: String,
    txn: Option<SignedChannelTransaction>,
}
trait ResponseFormat {
    fn format(state: bool, channel_sequence_number: u64, reason: String) -> ResponseResult;
}

impl ResponseFormat for ResponseResult {
    fn format(state: bool, channel_sequence_number: u64, reason: String) -> ResponseResult {
        ResponseResult {
            state,
            channel_sequence_number,
            reason,
            txn: None,
        }
    }
}

struct WebServer {
    node: Arc<Node_Internal>,
}

impl NewService for WebServer {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = Error;
    type Service = WebServer;
    type Future = Box<dyn Future<Item = Self::Service, Error = Self::InitError> + Send>;
    type InitError = Error;

    fn new_service(&self) -> Self::Future {
        Box::new(futures01::future::ok(Self {
            node: self.node.clone(),
        }))
    }
}

impl Service for WebServer {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = Error;
    type Future = Box<dyn Future<Item = Response<Body>, Error = Error> + Send>;

    fn call(&mut self, req: Request<Self::ReqBody>) -> Self::Future {
        let mut response = Response::new(Body::empty());
        let node_internal = self.node.clone();
        response.headers_mut().append(
            "Access-Control-Allow-Origin",
            "*".to_string().parse().unwrap(),
        );
        match req.uri().path() {
            "/exec" => {
                let resp = req.into_body().concat2().map(move |chunk| {
                    let body = chunk.iter().cloned().collect::<Vec<u8>>();
                    let json_args: Value = serde_json::from_slice(body.as_slice()).unwrap();
                    info!("exec interface args is {:?}", json_args);
                    let mut result: ResponseResult =
                        ResponseResult::format(false, 0, "fail".to_string());
                    let address = json_args.get("address").unwrap().as_str().unwrap();
                    let package_name = json_args.get("package_name").unwrap().as_str().unwrap();
                    let script_name = json_args.get("script_name").unwrap().as_str().unwrap();
                    let args = json_args.get("args").unwrap().as_str().unwrap();
                    let mut args_error = true;
                    if address.is_empty() {
                        result.reason = "address is null".to_string();
                    } else {
                        args_error = false;
                    }
                    if package_name.is_empty() {
                        result.reason = "package name is null".to_string();
                    } else {
                        args_error = false;
                    }
                    if script_name.is_empty() {
                        result.reason = "scripts is null".to_string();
                    } else {
                        args_error = false;
                    }
                    if !args_error {
                        let mut arguments: Vec<_> = Vec::new();
                        if !args.is_empty() {
                            let arg_vec: Vec<_> = args.split(',').collect();
                            arguments = arg_vec
                                .iter()
                                .filter_map(|arg| parse_as_transaction_argument(arg).ok())
                                .collect();
                        }

                        match node_internal.execute_script_with_argument(
                            AccountAddress::from_hex_literal(&address).unwrap_or_default(),
                            package_name.to_owned(),
                            script_name.to_owned(),
                            arguments,
                        ) {
                            Ok(msg_future) => {
                                result.state = true;
                                result.reason = "OK".to_string();
                                result.channel_sequence_number = msg_future.wait().unwrap();
                            }
                            Err(e) => {
                                result.reason = format!("Failed to execute request: {}", e);
                            }
                        };
                    }

                    *response.body_mut() = Body::from(
                        json!({
                            "status": result.state,
                            "channel_sequence_number": result.channel_sequence_number,
                            "reason": result.reason
                        })
                        .to_string(),
                    );
                    info!("response :{:?}", response.body_mut());
                    response
                });
                return Box::new(resp);
            }
            "/query" => {
                let resp = req.into_body().concat2().map(move |chunk| {
                    let body = chunk.iter().cloned().collect::<Vec<u8>>();
                    let json_args: Value = serde_json::from_slice(body.as_slice()).unwrap();
                    info!("query interface args is {:?}", json_args);
                    let mut result: ResponseResult =
                        ResponseResult::format(false, 0, "fail".to_string());
                    let participant_address = json_args.get("address").unwrap().as_str().unwrap();
                    let participant_address =
                        AccountAddress::from_hex_literal(&participant_address).unwrap_or_default();
                    let channel_sequence_number = json_args
                        .get("channel_sequence_number")
                        .unwrap()
                        .as_u64()
                        .unwrap();

                    match node_internal.get_txn_by_channel_sequence_number(
                        participant_address,
                        channel_sequence_number,
                    ) {
                        Ok(txn) => {
                            result.state = true;
                            result.reason = "OK".to_string();
                            result.txn = Some(txn);
                        }
                        Err(e) => {
                            result.reason = format!("Failed to execute request: {}", e);
                        }
                    };

                    *response.body_mut() = Body::from(
                        json!({
                            "status": result.state,
                            "txn": result.txn.clone(),
                        })
                        .to_string(),
                    );
                    info!("response :{:?}", response.body_mut());
                    response
                });
                return Box::new(resp);
            }
            _ => {
                *response.status_mut() = StatusCode::NOT_FOUND;
            }
        }
        Box::new(futures01::future::ok(response))
    }
}

impl WebServer {
    fn start(self, address: String, port: u16) {
        let addr = format!("{}:{}", address, port).parse().unwrap();
        let server = Server::bind(&addr)
            .serve(self)
            .map_err(|e| eprintln!("error: {}", e));
        info!("Serving HTTP at {}", addr);
        hyper::rt::run(server);
    }
}
