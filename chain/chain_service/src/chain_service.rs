use failure::prelude::*;
use types::proto::{access_path::AccessPath};
use types::{transaction::{SignedTransaction, TransactionPayload, Program}, language_storage::StructTag, write_set::WriteSet, account_address::AccountAddress, vm_error::VMStatus};
use proto_conv::FromProto;
use futures::{sync::mpsc::{unbounded, UnboundedReceiver}, future::Future, sink::Sink, stream::Stream};
use super::pub_sub;
use hex;
use grpcio::WriteFlags;
use state_storage::StateStorage;
use super::transaction_storage::TransactionStorage;
use std::{sync::{Arc, Mutex}};
use crypto::{hash::CryptoHash, HashValue};
use grpc_helpers::provide_grpc_response;
use vm_genesis::{encode_genesis_transaction, GENESIS_KEYPAIR};
use std::convert::TryFrom;
use metrics::IntGauge;
use futures03::{
    future::{FutureExt, TryFutureExt},
    stream::StreamExt,
    sink::SinkExt,
    executor::block_on,
};
use tokio::{runtime::Runtime};
use star_types::{offchain_transaction::OffChainTransaction,
                 proto::{chain_grpc::Chain,
                         chain::{LeastRootRequest, LeastRootResponse,
                                 FaucetRequest, FaucetResponse,
                                 GetAccountStateWithProofByStateRootRequest, GetAccountStateWithProofByStateRootResponse, Blob,
                                 WatchTransactionRequest, WatchTransactionResponse,
                                 MempoolAddTransactionStatus, MempoolAddTransactionStatusCode,
                                 SubmitTransactionRequest, SubmitTransactionResponse,
                                 StateByAccessPathResponse, AccountResource,
                         },
                         off_chain_transaction::OffChainTransaction as OffChainTransactionProto,
                 }};
use vm_runtime::{MoveVM, VMVerifier, VMExecutor};
use lazy_static::lazy_static;
use config::config::{VMConfig, VMPublishingOption};
use struct_cache::StructCache;
use vm::file_format::{CompiledModule, StructDefinition};
use core::borrow::Borrow;
use vm_runtime_types::loaded_data::struct_def::StructDef;

lazy_static! {
    static ref VM_CONFIG:VMConfig = VMConfig{
        publishing_options: VMPublishingOption::Open
    };
}

#[derive(Clone)]
pub struct ChainService {
    sender: channel::Sender<TransactionInner>,
    state_db: Arc<Mutex<StateStorage>>,
    tx_db: Arc<Mutex<TransactionStorage>>,
    vm: Arc<Mutex<MoveVM>>,
    struct_cache: Arc<Mutex<StructCache>>,
}

#[derive(Clone, Debug)]
pub enum TransactionInner {
    OnChain(SignedTransaction),
    OffChain(OffChainTransaction),
}

impl ChainService {
    pub fn new(rt: &mut Runtime) -> Self {
        let gauge = IntGauge::new("receive_transaction_channel_counter", "receive transaction channel").unwrap();
        let (mut tx_sender, mut tx_receiver) = channel::new(1_024, &gauge);
        let tx_db = Arc::new(Mutex::new(TransactionStorage::new()));
        let state_db = Arc::new(Mutex::new(StateStorage::new()));
        let vm = Arc::new(Mutex::new(MoveVM::new(&VM_CONFIG)));
        let struct_cache = Arc::new(Mutex::new(StructCache::new()));
        let chain_service = ChainService { sender: tx_sender.clone(), state_db, tx_db, vm, struct_cache };
        let chain_service_clone = chain_service.clone();

        let receiver_future = async move {
            while let Some(tx) = tx_receiver.next().await {
                chain_service_clone.submit_transaction_real(tx);
            }
        };
        rt.spawn(receiver_future.boxed().unit_error().compat());

        let genesis_checked_txn = encode_genesis_transaction(&GENESIS_KEYPAIR.0, GENESIS_KEYPAIR.1.clone());
        let genesis_txn = genesis_checked_txn.into_inner();
        let mut tx_sender_2 = tx_sender.clone();
        let genesis_future = async move {
            tx_sender_2.send(TransactionInner::OnChain(genesis_txn)).await.unwrap();
        };
        rt.spawn(genesis_future.boxed().unit_error().compat());

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

    fn apply_off_chain_transaction(&self, sign_tx: OffChainTransaction) {
        unimplemented!()
    }

    fn apply_on_chain_transaction(&self, sign_tx: SignedTransaction) {
        let signed_tx_hash = sign_tx.clone().hash();
        let mut tx_db = self.tx_db.lock().unwrap();
        let exist_flag = tx_db.exist_signed_transaction(signed_tx_hash);
        if !exist_flag {
            // 1. state_root
            let payload = sign_tx.clone().payload().clone();
            match payload {
                TransactionPayload::WriteSet(ws) => {
                    let mut state_db = self.state_db.lock().unwrap();
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

                    tx_db.insert_all(state_hash, sign_tx);
                }
                TransactionPayload::Program(program) => {
                    let mut state_db = self.state_db.lock().unwrap();
                    let mut output_vec = MoveVM::execute_block(vec![sign_tx.clone()], &VM_CONFIG, &*state_db);

                    output_vec.pop().and_then(|output| {
                        let state_hash = state_db.apply_write_set(&output.write_set()).unwrap();
                        tx_db.insert_all(state_hash, sign_tx);
                        Some(())
                    });
                }
            }
        }
    }

    pub async fn submit_transaction_inner(&self, mut sender: channel::Sender<TransactionInner>, inner_tx: TransactionInner) {
        sender.send(inner_tx).await.unwrap();
    }

    pub fn watch_transaction_inner(&self, address: Vec<u8>) -> UnboundedReceiver<WatchTransactionResponse> {
        let (sender, receiver) = unbounded::<WatchTransactionResponse>();
        let id = hex::encode(address);
        pub_sub::subscribe(id, sender.clone());

        receiver
    }

    pub fn least_state_root_inner(&self) -> HashValue {
        self.tx_db.lock().unwrap().least_hash_root()
    }

    pub fn get_account_state_with_proof_by_state_root_inner(&self, account_address: AccountAddress) -> Option<Vec<u8>> {
        let state_db = self.state_db.lock().unwrap();
        state_db.get_account_state(&account_address).map(|state| state.to_bytes())
    }

    pub fn state_by_access_path_inner(&self, account_address: AccountAddress, path: Vec<u8>) -> Option<Vec<u8>> {
        let state_db = self.state_db.lock().unwrap();
        state_db.get_account_state(&account_address).and_then(|state| state.get(&path))
    }

    pub fn faucet_inner(&self, account_address: AccountAddress, amount: u64) -> Result<HashValue> {
        let mut state_db = self.state_db.lock().unwrap();
        state_db.create_account(account_address, amount)
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
        }).and_then(|_root_hash| {
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
            let submit_txn_pb = req.signed_txn.clone().unwrap();
            Ok((signed_txn, submit_txn_pb))
        }).and_then(|(signed_txn, submit_txn_pb)| {
            block_on(self.submit_transaction_inner(self.sender.clone(), TransactionInner::OnChain(signed_txn.clone())));
            let mut wt_resp = WatchTransactionResponse::new();
            wt_resp.set_signed_txn(submit_txn_pb);
            pub_sub::send(wt_resp)?;

            let mut submit_resp = SubmitTransactionResponse::new();
            let mut state = MempoolAddTransactionStatus::new();
            state.set_code(MempoolAddTransactionStatusCode::Valid);
            submit_resp.set_mempool_status(state);
            Ok(submit_resp)
        });

        provide_grpc_response(resp, ctx, sink);
    }

    fn submit_off_chain_transaction(&mut self, ctx: ::grpcio::RpcContext, req: OffChainTransactionProto,
                                    sink: ::grpcio::UnarySink<SubmitTransactionResponse>) {
        let resp = OffChainTransaction::from_proto(req.clone()).and_then(|off_chain_tx| {
            let submit_txn_pb = req.transaction.clone().unwrap();
            Ok((off_chain_tx, submit_txn_pb))
        }).and_then(|(off_chain_tx, submit_txn_pb)| {
            block_on(self.submit_transaction_inner(self.sender.clone(), TransactionInner::OffChain(off_chain_tx)));
            let mut wt_resp = WatchTransactionResponse::new();
            wt_resp.set_signed_txn(submit_txn_pb);
            pub_sub::send(wt_resp)?;

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
        let receiver = self.watch_transaction_inner(req.address);
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
                            req: AccessPath,
                            sink: ::grpcio::UnarySink<StateByAccessPathResponse>) {
        let resp = AccountAddress::try_from(req.get_address().to_vec()).and_then(|account_address| {
            Ok(self.state_by_access_path_inner(account_address, req.path))
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
    use types::{account_address::AccountAddress, transaction::{Program, RawTransaction}};
    use std::{time::Duration};

    #[test]
    fn test_genesis() {
        let genesis_checked_txn = encode_genesis_transaction(&GENESIS_KEYPAIR.0, GENESIS_KEYPAIR.1.clone());
        let genesis_txn = genesis_checked_txn.into_inner();
        println!("{:?}", genesis_txn);
    }

    #[test]
    fn test_chain_service() {
        let mut rt = Runtime::new().unwrap();
        let chain_service = ChainService::new(&mut rt);
        let print_future = async move {
            let ten_millis = time::Duration::from_millis(100);
            thread::sleep(ten_millis);
            let root = chain_service.least_state_root_inner();
            println!("{:?}", root);
        };
        rt.block_on(print_future.boxed().unit_error().compat()).unwrap();
    }

    #[test]
    fn test_program() {
        let code =
            "
            main() {
                let x: u64;
                if (42 > 0) {
                    x = 1;
                } else {
                    return;
                }
                return;
            }
            ";

        let compiler = Compiler {
            code,
            ..Compiler::default()
        };

        let program = compiler.into_program(vec![]).unwrap();

        let account_address = AccountAddress::random();

        let signed_tx = RawTransaction::new(
            account_address,
            1 as u64,
            program,
            10_000 as u64,
            1 as u64,
            Duration::from_secs(u64::max_value()),
        ).sign(&GENESIS_KEYPAIR.0, GENESIS_KEYPAIR.1.clone())
            .unwrap()
            .into_inner();

        let mut rt = Runtime::new().unwrap();
        let chain_service = ChainService::new(&mut rt);
        chain_service.apply_on_chain_transaction(signed_tx);
    }
}
