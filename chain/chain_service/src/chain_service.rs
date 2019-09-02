use failure::prelude::*;
use types::proto::{access_path::AccessPath as ProtoAccessPath};
use types::{account_config::association_address, transaction::{SignedTransaction, TransactionPayload, RawTransaction}, access_path::AccessPath, account_address::AccountAddress};
use futures::{sync::mpsc::{unbounded, UnboundedReceiver}, future::Future, sink::Sink, stream::Stream};
use super::pub_sub;
use grpcio::WriteFlags;
use state_storage::StateStorage;
use super::transaction_storage::TransactionStorage;
use std::{sync::{Arc, Mutex}, time::Duration, convert::TryFrom};
use crypto::{hash::CryptoHash, HashValue};
use grpc_helpers::provide_grpc_response;
use vm_genesis::{encode_genesis_transaction, encode_transfer_program, encode_create_account_program, GENESIS_KEYPAIR};
use metrics::IntGauge;
use futures03::{
    future::{FutureExt, TryFutureExt},
    stream::StreamExt,
    sink::SinkExt,
    executor::block_on,
};
use tokio::{runtime::TaskExecutor};
use star_types::{channel_transaction::ChannelTransaction,
                 proto::{chain_grpc::Chain,
                         chain::{LeastRootRequest, LeastRootResponse,
                                 FaucetRequest, FaucetResponse,
                                 GetAccountStateWithProofByStateRootRequest, GetAccountStateWithProofByStateRootResponse, Blob,
                                 WatchTransactionRequest, WatchTransactionResponse,
                                 MempoolAddTransactionStatus, MempoolAddTransactionStatusCode,
                                 SubmitTransactionRequest, SubmitTransactionResponse,
                                 StateByAccessPathResponse, AccountResource,
                                 WatchEventRequest, WatchEventResponse,
                                 GetTransactionByHashRequest, GetTransactionByHashResponse,
                         },
                         channel_transaction::ChannelTransaction as OffChainTransactionProto,
                 }};
use vm_runtime::{MoveVM, VMExecutor};
use lazy_static::lazy_static;
use config::config::{VMConfig};
use state_view::StateView;
use core::borrow::Borrow;
use proto_conv::{FromProto, IntoProto};
use types::contract_event::ContractEvent;
use types::event::EventKey;

lazy_static! {
    static ref VM_CONFIG:VMConfig = VMConfig::onchain();
}

#[derive(Clone)]
pub struct ChainService {
    sender: channel::Sender<TransactionInner>,
    state_db: Arc<Mutex<StateStorage>>,
    tx_db: Arc<Mutex<TransactionStorage>>,
    tx_pub: Arc<Mutex<pub_sub::Pub<WatchTransactionResponse>>>,
    event_pub: Arc<Mutex<pub_sub::Pub<WatchEventResponse>>>,
}

#[derive(Clone, Debug)]
pub enum TransactionInner {
    OnChain(SignedTransaction),
    OffChain(ChannelTransaction),
}

impl ChainService {
    pub fn new(exe: &TaskExecutor) -> Self {
        let gauge = IntGauge::new("receive_transaction_channel_counter", "receive transaction channel").unwrap();
        let (tx_sender, mut tx_receiver) = channel::new(1_024, &gauge);
        let tx_db = Arc::new(Mutex::new(TransactionStorage::new()));
        let state_db = Arc::new(Mutex::new(StateStorage::new()));
        let tx_pub = Arc::new(Mutex::new(pub_sub::Pub::new()));
        let event_pub = Arc::new(Mutex::new(pub_sub::Pub::new()));
        let chain_service = ChainService { sender: tx_sender.clone(), state_db, tx_db, tx_pub, event_pub };
        let chain_service_clone = chain_service.clone();

        let receiver_future = async move {
            while let Some(tx) = tx_receiver.next().await {
                chain_service_clone.submit_transaction_real(tx);
            }
        };
        exe.spawn(receiver_future.boxed().unit_error().compat());

        let genesis_checked_txn = encode_genesis_transaction(&GENESIS_KEYPAIR.0, GENESIS_KEYPAIR.1.clone());
        let genesis_txn = genesis_checked_txn.into_inner();
        chain_service.apply_on_chain_transaction(genesis_txn);

        chain_service
    }

    fn submit_transaction_real(&self, tx: TransactionInner) {
        match tx {
            TransactionInner::OnChain(on_chain_tx) => {
                self.apply_on_chain_transaction(on_chain_tx)
            }
            TransactionInner::OffChain(off_chain_tx) => {
                self.apply_off_chain_transaction(off_chain_tx)
            }
        }
    }

    fn apply_off_chain_transaction(&self, off_chain_tx: ChannelTransaction) {
        let signed_tx_hash = off_chain_tx.txn().hash();
        let mut tx_db = self.tx_db.lock().unwrap();
        let exist_flag = tx_db.exist_signed_transaction(signed_tx_hash);
        if !exist_flag {
            let state_db = self.state_db.lock().unwrap();
            let output = off_chain_tx.output();
            let state_hash = state_db.apply_txn(&off_chain_tx).unwrap();
            tx_db.insert_all(state_hash, off_chain_tx.txn().clone());

            let event_lock = self.event_pub.lock().unwrap();
            output.events().iter().for_each(|e| {
                let event = e.clone().into_proto();
                let mut event_resp = WatchEventResponse::new();
                event_resp.set_event(event);
                event_lock.send(event_resp).unwrap();
            });

            let mut wt_resp = WatchTransactionResponse::new();
            wt_resp.set_signed_txn(off_chain_tx.txn().clone().into_proto());

            let tx_lock = self.tx_pub.lock().unwrap();
            tx_lock.send(wt_resp).unwrap();
        }
    }

    fn apply_on_chain_transaction(&self, sign_tx: SignedTransaction) {
        let signed_tx_hash = sign_tx.borrow().hash();
        let mut tx_db = self.tx_db.lock().unwrap();
        let exist_flag = tx_db.exist_signed_transaction(signed_tx_hash);
        if !exist_flag {
            // 1. state_root
            let payload = sign_tx.borrow().payload().borrow();
            match payload {
                TransactionPayload::WriteSet(ws) => {
                    let state_db = self.state_db.lock().unwrap();
                    let state_hash = state_db.apply_write_set(&ws).unwrap();
                    //let state_hash = SparseMerkleTree::default().root_hash();

//                    // 2. add signed_tx
//                    let version = tx_db.insert_signed_transaction(sign_tx.clone());
//
//                    // 3. tx_info
//                    let tx_info = TransactionInfo::new(signed_tx_hash, state_hash, HashValue::random(), 0);
//                    tx_db.insert_transaction_info(tx_info.clone());
//
//                    // 4. accumulator hash，store Version-HASH
//                    let hash_root = tx_db.accumulator_append(tx_info);
//                    tx_db.insert_ledger_info(hash_root);

                    tx_db.insert_all(state_hash, sign_tx.clone());
                }
                TransactionPayload::Program(_) | TransactionPayload::Module(_) | TransactionPayload::Script(_) => {
                    let state_db = self.state_db.lock().unwrap();
                    let mut output_vec = MoveVM::execute_block(vec![sign_tx.clone()], &VM_CONFIG, &*state_db);
                    output_vec.pop().and_then(|output| {
                        let state_hash = state_db.apply_libra_output(&output).unwrap();
                        tx_db.insert_all(state_hash, sign_tx.clone());

                        let event_lock = self.event_pub.lock().unwrap();
                        output.events().iter().for_each(|e| {
                            let event = e.clone().into_proto();
                            let mut event_resp = WatchEventResponse::new();
                            event_resp.set_event(event);
                            event_lock.send(event_resp).unwrap();
                        });

                        Some(())
                    });
                }
            }

            let mut wt_resp = WatchTransactionResponse::new();
            wt_resp.set_signed_txn(sign_tx.into_proto());

            let tx_lock = self.tx_pub.lock().unwrap();
            tx_lock.send(wt_resp).unwrap();
        }
    }

    pub async fn submit_transaction_inner(&self, mut sender: channel::Sender<TransactionInner>, inner_tx: TransactionInner) {
        sender.send(inner_tx).await.unwrap();
    }

    pub fn watch_transaction_inner(&self, address: AccountAddress, index: u64) -> UnboundedReceiver<WatchTransactionResponse> {
        if index != std::u64::MAX {
            //TODO
            //1. get least tx index
            //2. compare index
            //3. get tx and send to client
        }

        let (sender, receiver) = unbounded::<WatchTransactionResponse>();
        let id = address.hash();
        let tx_lock = self.tx_pub.lock().unwrap();
        tx_lock.subscribe(id, sender, Box::new(move |mut tx: WatchTransactionResponse| -> bool {
            let signed_tx = SignedTransaction::from_proto(tx.take_signed_txn()).unwrap();
            signed_tx.sender() == address
        }));

        receiver
    }

    pub fn watch_event_inner(&self, address: AccountAddress, keys: Vec<EventKey>, _index: u64) -> UnboundedReceiver<WatchEventResponse> {
        let (sender, receiver) = unbounded::<WatchEventResponse>();
        let id = address.hash();
        let event_lock = self.event_pub.lock().unwrap();
        event_lock.subscribe(id, sender, Box::new(move |event: WatchEventResponse| -> bool {
            let mut flag = false;
            let event: ContractEvent = ContractEvent::from_proto(event.get_event().clone()).unwrap();
            keys.iter().for_each(|key| {
                flag = key == event.key()
            });

            flag
        }));

        receiver
    }

    pub fn least_state_root_inner(&self) -> HashValue {
        self.tx_db.lock().unwrap().least_hash_root()
    }

    pub fn get_account_state_with_proof_by_state_root_inner(&self, account_address: AccountAddress) -> Option<Vec<u8>> {
        let state_db = self.state_db.lock().unwrap();
        state_db.get_account_state(&account_address)
    }

    pub fn state_by_access_path_inner(&self, account_address: AccountAddress, path: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let state_db = self.state_db.lock().unwrap();
        state_db.get(&AccessPath::new(account_address, path))
    }

    pub fn faucet_inner(&self, receiver: AccountAddress, amount: u64) -> Result<()> {
        let state_db = self.state_db.lock().unwrap();
        let exist_flag = state_db.exist_account(&receiver);
        let program = if !exist_flag {
            encode_create_account_program(&receiver, amount)
        } else {
            encode_transfer_program(&receiver, amount)
        };

        let sender = association_address();//AccountAddress::from_public_key(&GENESIS_KEYPAIR.1);
        let s_n = match state_db.sequence_number(&sender) {
            Some(num) => num,
            _ => 0
        };
        drop(state_db);
        let signed_tx = RawTransaction::new(
            sender,
            s_n,
            program,
            1000_000 as u64,
            1 as u64,
            Duration::from_secs(u64::max_value()),
        ).sign(&GENESIS_KEYPAIR.0, GENESIS_KEYPAIR.1.clone())
            .unwrap()
            .into_inner();

        self.apply_on_chain_transaction(signed_tx);
        Ok(())
    }

    pub fn sender(&self) -> channel::Sender<TransactionInner> {
        self.sender.clone()
    }

    pub fn get_transaction_by_hash(&self,hash:HashValue)->Result<SignedTransaction>{
        let lock = self.tx_db.lock().unwrap();
        let signed_tx = lock.get_signed_transaction_by_hash(&hash);
        match signed_tx {
            Some(tx) => Ok(tx),
            None => bail!("could not find tx by hash {}",hash),
        }
    }
}

impl Chain for ChainService {
    fn least_state_root(&mut self, ctx: ::grpcio::RpcContext, _req: LeastRootRequest, sink: ::grpcio::UnarySink<LeastRootResponse>) {
        let least_hash_root = self.least_state_root_inner();
        let mut resp = LeastRootResponse::new();
        resp.set_state_root_hash(least_hash_root.to_vec());
        provide_grpc_response(Ok(resp), ctx, sink);
    }

    fn faucet(&mut self, ctx: ::grpcio::RpcContext,
              req: FaucetRequest,
              sink: ::grpcio::UnarySink<FaucetResponse>) {
        let resp = AccountAddress::try_from(req.get_address().to_vec()).and_then(|account_address| {
            self.faucet_inner(account_address, req.get_amount())
        }).and_then(|_| {
            Ok(FaucetResponse::new())
        });
        provide_grpc_response(resp, ctx, sink);
    }

    fn get_account_state_with_proof_by_state_root(&mut self, ctx: ::grpcio::RpcContext,
                                                  req: GetAccountStateWithProofByStateRootRequest,
                                                  sink: ::grpcio::UnarySink<GetAccountStateWithProofByStateRootResponse>) {
        let resp = AccountAddress::try_from(req.get_address().to_vec()).and_then(|account_address| {
            Ok(self.get_account_state_with_proof_by_state_root_inner(account_address))
        }).and_then(|a_s_bytes| {
            let mut get_resp = GetAccountStateWithProofByStateRootResponse::new();
            match a_s_bytes {
                Some(a_s) => {
                    let mut blob = Blob::new();
                    blob.set_blob(a_s);
                    get_resp.set_account_state_blob(blob);
                }
                None => {}
            };
            Ok(get_resp)
        });
        provide_grpc_response(resp, ctx, sink);
    }

    fn submit_transaction(&mut self, ctx: ::grpcio::RpcContext,
                          req: SubmitTransactionRequest,
                          sink: ::grpcio::UnarySink<SubmitTransactionResponse>) {
        let resp = SignedTransaction::from_proto(req.signed_txn.clone().unwrap()).and_then(|signed_txn| {
            block_on(self.submit_transaction_inner(self.sender.clone(), TransactionInner::OnChain(signed_txn)));

            let mut submit_resp = SubmitTransactionResponse::new();
            let mut state = MempoolAddTransactionStatus::new();
            state.set_code(MempoolAddTransactionStatusCode::Valid);
            submit_resp.set_mempool_status(state);
            Ok(submit_resp)
        });

        provide_grpc_response(resp, ctx, sink);
    }

    fn submit_channel_transaction(&mut self, ctx: ::grpcio::RpcContext, req: OffChainTransactionProto,
                                    sink: ::grpcio::UnarySink<SubmitTransactionResponse>) {
        let resp = ChannelTransaction::from_proto(req.clone()).and_then(|off_chain_tx| {
            block_on(self.submit_transaction_inner(self.sender.clone(), TransactionInner::OffChain(off_chain_tx)));

            let mut submit_resp = SubmitTransactionResponse::new();
            let mut state = MempoolAddTransactionStatus::new();
            state.set_code(MempoolAddTransactionStatusCode::Valid);
            submit_resp.set_mempool_status(state);
            Ok(submit_resp)
        });

        provide_grpc_response(resp, ctx, sink);
    }

    fn watch_transaction(&mut self, ctx: ::grpcio::RpcContext,
                         req: WatchTransactionRequest,
                         sink: ::grpcio::ServerStreamingSink<WatchTransactionResponse>) {
        let index = if req.has_index() {
            req.get_index()
        } else {
            std::u64::MAX
        };
        let receiver = self.watch_transaction_inner(AccountAddress::from_proto(req.address).unwrap(), index);
        let stream = receiver
            .map(|e| (e, WriteFlags::default()))
            .map_err(|_| grpcio::Error::RemoteStopped);

        ctx.spawn(
            sink
                .send_all(stream)
                .map(|_| println!("completed"))
                .map_err(|e| println!("failed to reply: {:?}", e)),
        );
    }

    fn state_by_access_path(&mut self, ctx: ::grpcio::RpcContext,
                            req: ProtoAccessPath,
                            sink: ::grpcio::UnarySink<StateByAccessPathResponse>) {
        let resp = AccountAddress::try_from(req.get_address().to_vec()).and_then(|account_address| {
            self.state_by_access_path_inner(account_address, req.path)
        }).and_then(|resource| {
            let mut state_resp = StateByAccessPathResponse::new();
            match resource {
                Some(re) => {
                    let mut a_r = AccountResource::new();
                    a_r.set_resource(re);
                    state_resp.set_account_resource(a_r);
                }
                _ => {}
            };
            Ok(state_resp)
        });

        provide_grpc_response(resp, ctx, sink);
    }

    fn watch_event(&mut self, ctx: ::grpcio::RpcContext,
                   req: WatchEventRequest,
                   sink: ::grpcio::ServerStreamingSink<WatchEventResponse>) {
        let index = if req.has_index() {
            req.get_index()
        } else {
            std::u64::MAX
        };
        let keys = req.get_keys().iter().map(|key| -> EventKey { EventKey::new(u8_32(key.get_key())) }).collect();
        let receiver = self.watch_event_inner(AccountAddress::try_from(req.get_address().to_vec()).unwrap(), keys, index);
        let stream = receiver
            .map(|e| (e, WriteFlags::default()))
            .map_err(|_| grpcio::Error::RemoteStopped);

        ctx.spawn(
            sink
                .send_all(stream)
                .map(|_| println!("completed"))
                .map_err(|e| println!("failed to reply: {:?}", e)),
        );
    }

    fn get_transaction_by_hash(&mut self, ctx: ::grpcio::RpcContext,
                               req: GetTransactionByHashRequest,
                               sink: ::grpcio::UnarySink<GetTransactionByHashResponse>) {
        let hash = HashValue::from_slice(req.get_state_root_hash()).unwrap();
        let mut resp = GetTransactionByHashResponse::new();
        let lock = self.tx_db.lock().unwrap();
        let signed_tx = lock.get_signed_transaction_by_hash(&hash);
        match signed_tx {
            Some(tx) => resp.set_signed_tx(tx.into_proto()),
            None => {}
        }
        provide_grpc_response(Ok(resp), ctx, sink);
    }
}

fn u8_32(value: &[u8]) -> [u8; 32] {
    let mut tmp = [0u8; 32];
    tmp.copy_from_slice(value);
    tmp
}

#[cfg(test)]
mod tests {
    use vm_genesis::{encode_genesis_transaction, GENESIS_KEYPAIR};
    use crate::chain_service::ChainService;
    use tokio::runtime::Runtime;
    use futures::future::Future;
    use futures03::{
        future::{FutureExt, TryFutureExt},
        stream::StreamExt,
        sink::SinkExt,
        executor::block_on,
    };
    use std::{thread, time};
    use compiler::Compiler;
    use types::{account_address::AccountAddress, transaction::{Program, RawTransaction}, account_config::{core_code_address, association_address}};
    use std::{time::Duration};
    use crypto::hash::{CryptoHash, TransactionInfoHasher};

    #[test]
    fn test_genesis() {
        let genesis_checked_txn = encode_genesis_transaction(&GENESIS_KEYPAIR.0, GENESIS_KEYPAIR.1.clone());
        let genesis_txn = genesis_checked_txn.into_inner();
        println!("{:?}", genesis_txn);
    }

    #[test]
    fn test_chain_service() {
        let mut rt = Runtime::new().unwrap();
        let chain_service = ChainService::new(&rt.executor());
//        let print_future = async move {
//            let ten_millis = time::Duration::from_millis(100);
//            thread::sleep(ten_millis);
        let root = chain_service.least_state_root_inner();
        println!("{:?}", root);
//        };
//        rt.block_on(print_future.boxed().unit_error().compat()).unwrap();
    }

    #[test]
    fn test_apply_program() {
        let rt = Runtime::new().unwrap();

        let code =
            "
            main() {
                return;
            }
            ";

        let compiler = Compiler {
            code,
            ..Compiler::default()
        };

        let program = compiler.into_program(vec![]).unwrap();

        let account_address = association_address();

        let chain_service = ChainService::new(&rt.executor());

        let state_db = chain_service.state_db.lock().unwrap();
        let s_n = state_db.sequence_number(&account_address).unwrap();
        drop(state_db);
        let signed_tx = RawTransaction::new(
            account_address,
            s_n as u64,
            program,
            1_000_000 as u64,
            1 as u64,
            Duration::from_secs(u64::max_value()),
        ).sign(&GENESIS_KEYPAIR.0, GENESIS_KEYPAIR.1.clone())
            .unwrap()
            .into_inner();

        chain_service.apply_on_chain_transaction(signed_tx);
    }

    #[test]
    fn test_faucet() {
        let mut rt = Runtime::new().unwrap();
        let chain_service = ChainService::new(&rt.executor());
        let receiver = AccountAddress::random();
        chain_service.faucet_inner(receiver, 100);
        let state_db = chain_service.state_db.lock().unwrap();
        let exist_flag = state_db.exist_account(&receiver);
        assert_eq!(exist_flag, true);
    }
}
