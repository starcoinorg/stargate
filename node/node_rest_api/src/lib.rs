#[macro_use]
extern crate serde_json;
use canonical_serialization::{CanonicalSerialize, SimpleSerializer};
use crypto::hash::HashValue;
use futures01::{
    Future,  Stream,
};
use hyper::{
    service::{NewService, Service},
    Body, Error, Request, Response, Server, StatusCode,
};
use sg_config::config::{ RestConfig};
use node_internal::node::Node as Node_Internal;
use sgchain::star_chain_client::ChainClient;
use std::{
    collections::HashMap,
    str::FromStr,
    sync::Arc,
    thread,
};
use libra_types::{account_address::AccountAddress, transaction::parse_as_transaction_argument};
use std::net::{SocketAddr, Ipv4Addr, IpAddr};


trait CompoundTrait: ChainClient + Clone + Send + Sync + 'static {}

pub fn setup_node_rest<C>(
        config: RestConfig,
    node: Arc<Node_Internal<C>>,
) -> Result<(), Box<dyn std::error::Error>>
where
    C: ChainClient + Clone + 'static,
{
    thread::spawn(move || {
        let web_server = WebServer { node };
        web_server.start(config.address.clone(), config.port);
    });
    Ok(())
}

//struct RequestForm {
//    address: String,
//    package_name: String,
//    script_name: String,
//    args: String,
//}

struct ResponseResult {
    state: bool,
    req_id: HashValue,
    reason: String,
}
trait ResponseFormat {
    fn format(state: bool, req_id: HashValue, reason: String) -> ResponseResult;
}

impl ResponseFormat for ResponseResult {
    fn format(state: bool, req_id: HashValue, reason: String) -> ResponseResult {
        ResponseResult {
            state,
            req_id,
            reason,
        }
    }
}

////TODO query transation interface
//#[get("/query", data = "<request>")]
//fn query(tid: u64) -> JsonValue {
//    json!({
//        "transation_id": 1000,
//        "transation_info": "scripts execute success."
//    })
//}

struct WebServer<C: ChainClient + Clone + 'static> {
    node: Arc<Node_Internal<C>>,
}

impl<C: ChainClient + Clone + 'static> NewService for WebServer<C> {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = Error;
    type Service = WebServer<C>;
    type Future = Box<dyn Future<Item = Self::Service, Error = Self::InitError> + Send>;
    type InitError = Error;

    fn new_service(&self) -> Self::Future {
        Box::new(futures01::future::ok(Self {
            node: self.node.clone(),
        }))
    }
}

impl<C: ChainClient + Clone + 'static> Service for WebServer<C> {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = Error;
    type Future = Box<dyn Future<Item = Response<Body>, Error = Error> + Send>;

    fn call(&mut self, req: Request<Self::ReqBody>) -> Self::Future {
        let mut response = Response::new(Body::empty());
        let node_internal = self.node.clone();

        match req.uri().path() {
            "/exec" => {
                let resp = req.into_body().concat2().map(move |chunk| {
                    let mut form = url::form_urlencoded::parse(chunk.as_ref())
                        .into_owned()
                        .collect::<HashMap<String, String>>();
                    let result: ResponseResult;
                    if let Some(address) = form.remove("address") {
                        let package_name = form.remove("package_name").unwrap();
                        let script_name = form.remove("script_name").unwrap();
                        let args = form.remove("args").unwrap();
                        let mut arguments: Vec<_> = Vec::new();
                        if !args.is_empty() {
                            let arg_vec: Vec<_> = args
                                .split(',')
                                .collect();
                            arguments = arg_vec.iter()
                                .filter_map(|arg| parse_as_transaction_argument(arg).ok())
                                .collect();
                        }

                        match node_internal.execute_script_with_argument(
                            AccountAddress::from_hex_literal(&address).unwrap_or_default(),
                            package_name,
                            script_name,
                            arguments,
                        ) {
                            Ok(msg_future) => {
                                result = ResponseResult::format(
                                    true,
                                    msg_future.wait().unwrap(),
                                    "OK".to_string(),
                                )
                            }
                            Err(e) => {
                                result = ResponseResult::format(
                                    false,
                                    HashValue::zero(),
                                    format!("Failed to execute request: {}", e),
                                )
                            }
                        };
                    } else {
                        result = ResponseResult::format(
                            false,
                            HashValue::zero(),
                            "addresss is null".to_string(),
                        )
                    }
                    //json format
                    *response.body_mut() = Body::from(
                        json!({
                            "status": result.state,
                            "req_id": result.req_id.to_string(),
                            "reason": result.reason
                        })
                        .to_string(),
                    );
                    response
                });
                return Box::new(resp);
            }
            "/query" => {
                let resp = req.into_body().concat2().map(move |chunk| {
                    let mut form = url::form_urlencoded::parse(chunk.as_ref())
                        .into_owned()
                        .collect::<HashMap<String, String>>();
                    let result: ResponseResult;
                    if let Some(tid) = form.remove("transation_id") {
                        let count_str: String = form.remove("count").unwrap_or("0".to_string());
                        let count = u32::from_str(&count_str).unwrap_or_default();
                        match node_internal
                            .find_offchain_txn(HashValue::from_slice(tid.as_bytes()).ok(), count)
                        {
                            Ok(msg_future) => {
                                result = ResponseResult::format(
                                    true,
                                    HashValue::zero(),
                                    "Ok".to_string(),
                                )
                            }
                            Err(e) => {
                                result = ResponseResult::format(
                                    false,
                                    HashValue::zero(),
                                    format!("Failed to execute request: {}", e),
                                )
                            }
                        };
                    } else {
                        result = ResponseResult::format(
                            false,
                            HashValue::zero(),
                            "transation id  is null".to_string(),
                        )
                    }
                    //json format
                    *response.body_mut() = Body::from(
                        json!({
                            "status": result.state,
                            "tids": result.reason
                        })
                        .to_string(),
                    );
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

impl<C: ChainClient + Clone + 'static> WebServer<C> {
    fn start(self, address: String, port: u16) {
        let addr = format!("{}:{}", address, port).parse().unwrap();
        let server = Server::bind(&addr)
            .serve(self)
            .map_err(|e| eprintln!("error: {}", e));
        println!("Serving HTTP at {}", addr);
        hyper::rt::run(server);
    }
}
