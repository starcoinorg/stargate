use failure::prelude::*;
use types::proto::{access_path::AccessPath as ProtoAccessPath, account_state_blob::{AccountStateBlob as AccountStateBlobProto, AccountStateWithProof}};
use types::{ledger_info::{LedgerInfo, LedgerInfoWithSignatures}, get_with_proof::RequestItem, proof::SparseMerkleProof, account_state_blob::AccountStateBlob, account_config::{association_address, core_code_address}, transaction::{TransactionToCommit, TransactionInfo, SignedTransaction, TransactionPayload, RawTransaction}, access_path::AccessPath, account_address::AccountAddress};
use futures::{sync::mpsc::{unbounded, UnboundedReceiver}, future::Future, sink::Sink, stream::Stream};
use super::pub_sub;
use grpcio::WriteFlags;
use state_cache::state_cache::{StateCache, AccountState};
use super::transaction_storage::TransactionStorage;
use std::{sync::{Arc, Mutex}, time::Duration, convert::TryFrom};
use crypto::{hash::{CryptoHash, GENESIS_BLOCK_ID}, HashValue, ed25519::Ed25519Signature};
use grpc_helpers::provide_grpc_response;
use vm_genesis::{encode_genesis_transaction, encode_transfer_program, encode_create_account_program, GENESIS_KEYPAIR};
use metrics::IntGauge;
use futures03::{
    future::{FutureExt, TryFutureExt},
    stream::StreamExt,
    sink::SinkExt,
    executor::block_on,
};
use tokio::runtime::{TaskExecutor, Runtime};
use star_types::{channel_transaction::ChannelTransaction,
                 proto::{chain_grpc::Chain,
                         chain::{LatestRootRequest, LatestRootResponse,
                                 FaucetRequest, FaucetResponse,
                                 GetAccountStateWithProofRequest, GetAccountStateWithProofResponse, Blob,
                                 WatchTransactionRequest,
                                 MempoolAddTransactionStatus, MempoolAddTransactionStatusCode,
                                 SubmitTransactionRequest, SubmitTransactionResponse,
                                 StateByAccessPathResponse, AccountResource,
                                 WatchEventRequest,
                                 GetTransactionByVersionRequest, GetTransactionResponse,
                                 GetTransactionBySeqNumRequest,
                                 WatchData, WatchTxData,
                         },
                         channel_transaction::ChannelTransaction as ChannelTransactionProto,
                 }, transaction_output_helper};
use vm_runtime::{MoveVM, VMExecutor};
use lazy_static::lazy_static;
use config::config::VMConfig;
use state_view::StateView;
use core::borrow::{Borrow, BorrowMut};
use proto_conv::{FromProto, IntoProto};
use types::contract_event::ContractEvent;
use types::event::EventKey;
use types::transaction::{TransactionOutput, TransactionStatus, Version};
use types::vm_error::VMStatus;
use super::event_storage::{gene_event_hash, EventStorage};
use atomic_refcell::AtomicRefCell;
use futures::sync::mpsc::UnboundedSender;
use futures::future::FutureResult;
use logger::prelude::*;
use libradb::LibraDB;
use std::collections::HashMap;
use std::path::Path;
use std::fs::create_dir_all;
use tools::tempdir::TempPath;
use libradb::data_storage::{DataStorage, ReadDataStorage, WriteData, ReadData};
use state_cache::data_view::{StateDataView, AccountReader};
use struct_cache::StructCache;
use std::sync::mpsc;

lazy_static! {
    static ref VM_CONFIG:VMConfig = VMConfig::onchain();
}

#[derive(Clone)]
pub struct ChainService {
    sender: channel::Sender<SignedTransaction>,
    tx_pub: Arc<pub_sub::Pub<Vec<AccountAddress>, WatchData>>,
    event_pub: Arc<pub_sub::Pub<Vec<AccountAddress>, WatchData>>,
    task_exe: TaskExecutor,
    libra_db: Arc<AtomicRefCell<DataStorage>>,
    read_db: Arc<AtomicRefCell<ReadDataStorage>>,
    pub state_view: Arc<StateDataView>,
}

impl Drop for ChainService {
    fn drop(&mut self) {
        info!("{}", "shutdown chain service.");
    }
}

impl ChainService {
    pub fn new(exe: &TaskExecutor, path_option: &Option<String>) -> (Self, mpsc::Receiver<()>) {
        let gauge = IntGauge::new("receive_transaction_channel_counter", "receive transaction channel").expect("create IntGauge err.");
        let (tx_sender, mut tx_receiver) = channel::new(1_024, &gauge);
        let tx_pub = Arc::new(pub_sub::Pub::new());
        let event_pub = Arc::new(pub_sub::Pub::new());

        let (genesis_flag, (db, receive)) = ChainService::init_db(path_option);
        let read_db = Arc::new(AtomicRefCell::new(db.read_db()));
        let state_view = Arc::new(StateDataView::new(Arc::new(db.read_db()), StructCache::new()));
        let libra_db = Arc::new(AtomicRefCell::new(db));

        let chain_service = ChainService { sender: tx_sender, tx_pub, event_pub, task_exe: exe.clone(), libra_db, read_db, state_view };
        let chain_service_clone = chain_service.clone();

        let receiver_future = async move {
            while let Some(tx) = tx_receiver.next().await {
                chain_service_clone.apply_on_chain_transaction(tx);
            };
        };

        exe.spawn(receiver_future.boxed().unit_error().compat());

        if !genesis_flag {
            let genesis_checked_txn = encode_genesis_transaction(&GENESIS_KEYPAIR.0, GENESIS_KEYPAIR.1.clone());
            let genesis_txn = genesis_checked_txn.into_inner();

            match genesis_txn.payload() {
                TransactionPayload::WriteSet(ws) => {
                    let (state_hash, accounts) = StateCache::apply_genesis_write_set(&chain_service.state_view, &ws).expect("apply genesis tx err.");

                    let signed_tx_hash = genesis_txn.hash();
                    let events: Vec<ContractEvent> = vec![];
                    let event_hash = gene_event_hash(&events).expect("genesis event hash err");
                    let tx_info = TransactionInfo::new(signed_tx_hash, state_hash, event_hash, 0);
                    let ledger_info = LedgerInfo::new(0, tx_info.hash(), HashValue::random(), *GENESIS_BLOCK_ID, 0, 0, None);
                    let ledger_info_with_sigs = LedgerInfoWithSignatures::new(ledger_info, HashMap::new());

                    chain_service.insert_into_libra(&Some(ledger_info_with_sigs), genesis_txn, &accounts, events, 0, true);
                }
                _ => {}
            };
        }
        (chain_service, receive)
    }

    fn init_db(path_option: &Option<String>) -> (bool, (DataStorage, mpsc::Receiver<()>)) {
        let (has_path, path) = match path_option {
            Some(p) => (true, p.as_str()),
            None => (false, "")
        };

        if has_path {
            let data_path = Path::new(&path);
            if !data_path.exists() {
                create_dir_all(data_path);
            }

            let db_path = if data_path.ends_with("/") {
                format!("{}{}", path, "libradb")
            } else {
                format!("{}{}", path, "/libradb")
            };

            let db_exist = Path::new(&db_path).exists();
            (db_exist, DataStorage::new(LibraDB::new(data_path)))
        } else {
            let tmp_dir = TempPath::new();
            tmp_dir.create_as_dir();
            let path = tmp_dir.path().display();
            info!("db path:{}", path);

            (false, DataStorage::new(LibraDB::new(format!("{}{}", path, "/libradb"))))
        }
    }

    fn apply_on_chain_transaction(&self, sign_tx: SignedTransaction) {
        let signed_tx_hash = sign_tx.borrow().hash();
        let ver = self.get_latest_version();
        let mut watch_tx = WatchTxData::new();
        let mut output_vec = MoveVM::execute_block(vec![sign_tx.clone()], &VM_CONFIG, &*self.state_view);
        let output = output_vec.pop().expect("output vec is empty.");
        info!("apply_on_chain_transaction tx:{}, output: {}", sign_tx.raw_txn().hash(), output);
        let (ver, account_vec) = match output.status() {
            TransactionStatus::Keep(_) => {
                let (state_hash, accounts) = StateCache::apply_libra_output(&self.state_view, &output).expect("apply output err.");
                let v = self.insert_into_libra(&None, sign_tx.clone(), &accounts, output.events().to_vec(), output.gas_used(), false);
                let addrs = accounts.iter().map(|(addr, blob)| -> AccountAddress { addr.clone() }).collect();
                (v, addrs)
            }
            _ => {
                (0, vec![])
            }
        };
        output.events().iter().for_each(|e| {
            let event = e.clone().into_proto();
            let mut event_resp = WatchData::new();
            event_resp.set_event(event);
            event_resp.set_version(ver);
            self.event_pub.send(account_vec.clone(), event_resp).unwrap();
        });

        watch_tx.set_output(transaction_output_helper::into_pb(output).expect("output to proto err."));

        let mut wt_resp = WatchData::new();
        watch_tx.set_signed_txn(sign_tx.into_proto());
        wt_resp.set_tx(watch_tx);
        wt_resp.set_version(ver);
        self.tx_pub.send(account_vec, wt_resp).unwrap();
    }

    fn insert_into_libra(&self, sign: &Option<LedgerInfoWithSignatures<Ed25519Signature>>, sign_tx: SignedTransaction, accounts: &Vec<(AccountAddress, AccountStateBlob)>, events: Vec<ContractEvent>, gas: u64, is_genesis: bool) -> Version {
        let mut map = HashMap::new();
        accounts.iter().for_each(|(addr, account)| {
            map.insert(*addr, account.clone());
        });
        let commit_tx = TransactionToCommit::new(sign_tx, map, events, gas);

        let libradb = self.libra_db.as_ref().borrow();
        if is_genesis {
            libradb.save_genesis_transactions(vec![commit_tx], sign).expect("save genesis transactions err.");
            0
        } else {
            let ver = self.get_latest_version() + 1;
            libradb.save_transactions(vec![commit_tx], ver).expect("save transactions err.");
            ver
        }
    }

    pub fn watch_transaction_inner(&self, address: AccountAddress, index: u64) -> UnboundedReceiver<WatchData> {
        if index != std::u64::MAX {
            //TODO
            //1. get latest tx index
            //2. compare index
            //3. get tx and send to client
        }

        let (sender, receiver) = unbounded::<WatchData>();
        //TODO id generate.
        let id = HashValue::random();
        self.tx_pub.subscribe(id, sender, Box::new(move |accounts: Vec<AccountAddress>, _tx: WatchData| -> bool {
            let mut addr_flag = false;
            accounts.iter().for_each(|addr| {
                if !addr_flag {
                    addr_flag = addr == &address
                }
            });

            addr_flag
        }));

        receiver
    }

    pub fn watch_event_inner(&self, address: AccountAddress, keys: Vec<EventKey>, _index: u64) -> UnboundedReceiver<WatchData> {
        let (sender, receiver) = unbounded::<WatchData>();
        let id = address.hash();
        self.event_pub.subscribe(id, sender, Box::new(move |_accounts: Vec<AccountAddress>, data: WatchData| -> bool {
            let mut key_flag = false;
            let event: ContractEvent = ContractEvent::from_proto(data.get_event().clone()).unwrap();
            keys.iter().for_each(|key| {
                if !key_flag {
                    key_flag = key == event.key()
                }
            });

            key_flag
        }));

        receiver
    }

    pub fn latest_state_root_inner(&self) -> HashValue {
        let read_db = self.read_db.as_ref().borrow();
        read_db.latest_state_root().expect("latest_state_root is none.")
    }

    pub fn get_latest_version(&self) -> Version {
        let read_db = self.read_db.as_ref().borrow();
        read_db.latest_version().expect("latest_version is none.")
    }

    pub fn get_account_state_inner(&self, account_address: &AccountAddress, ver: Option<u64>) -> Option<Vec<u8>> {
        let version = match ver {
            Some(v) => { v }
            None => {
                self.get_latest_version()
            }
        };
        StateCache::get_account_state_by_version(&self.state_view, version, account_address)
    }

    pub fn get_account_state_with_proof_inner(&self, account_address: &AccountAddress, ver: Option<u64>) -> Option<(u64, Option<AccountStateBlob>, SparseMerkleProof)> {
        let version = match ver {
            Some(v) => v,
            None => { self.state_view.latest_version().expect("latest version is none.") }
        };

        StateCache::account_state_with_proof(&self.state_view, version, account_address)
    }

    pub fn state_by_access_path_inner(&self, account_address: AccountAddress, path: Vec<u8>) -> Result<Option<Vec<u8>>> {
        Ok(StateCache::get_by_access_path_by_version(&self.state_view, self.state_view.latest_version().expect("latest_version is none."), &AccessPath::new(account_address, path)))
    }

    pub fn faucet_inner(&self, receiver: AccountAddress, amount: u64) -> Result<()> {
        let exist_flag = StateCache::exist_account(&self.state_view, self.state_view.latest_version().expect("latest_version is none."), &receiver);
        let program = if !exist_flag {
            encode_create_account_program(&receiver, amount)
        } else {
            encode_transfer_program(&receiver, amount)
        };

        let sender = association_address();//AccountAddress::from_public_key(&GENESIS_KEYPAIR.1);
        let s_n = match StateCache::sequence_number_by_version(&self.state_view, self.state_view.latest_version().expect("latest version is none."), &sender) {
            Some(num) => num,
            _ => 0
        };
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

    pub fn send_tx(&self, txn: SignedTransaction) {
        let mut sender_tmp = self.sender.clone();
        let send_future = async move {
            sender_tmp.send(txn).await.unwrap();
        };

        self.task_exe.clone().spawn(send_future.boxed().unit_error().compat());
    }

    pub fn get_transaction_by_ver(&self, ver: Version) -> Result<SignedTransaction> {
        let read_db = self.read_db.as_ref().borrow();
        let mut proof = read_db.get_transactions(ver, 1, ver, false)?;
        Ok(proof.transaction_and_infos.pop().expect("tx is none.").0)
    }

    pub fn get_transaction_by_seq_num_inner(&self, account_address: AccountAddress, seq_num: u64) -> Result<SignedTransaction> {
        let read_db = self.read_db.as_ref().borrow();
        let req = RequestItem::GetAccountTransactionBySequenceNumber { account: account_address, sequence_number: seq_num, fetch_events: false };
        let mut resp = read_db.update_to_latest_ledger(0, vec![req])?;
        let proof = resp.get(0).expect("res is none.").clone().into_get_account_txn_by_seq_num_response()?.0.expect("tx is none.");
        Ok(proof.signed_transaction)
    }
}

impl Chain for ChainService {
    fn latest_state_root(&mut self, ctx: ::grpcio::RpcContext, _req: LatestRootRequest, sink: ::grpcio::UnarySink<LatestRootResponse>) {
        let latest_hash_root = self.latest_state_root_inner();
        let mut resp = LatestRootResponse::new();
        resp.set_state_root_hash(latest_hash_root.to_vec());
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

    fn get_account_state_with_proof(&mut self, ctx: ::grpcio::RpcContext,
                                    req: GetAccountStateWithProofRequest,
                                    sink: ::grpcio::UnarySink<GetAccountStateWithProofResponse>) {
        let resp = AccountAddress::try_from(req.get_address().to_vec()).and_then(|account_address| {
            let ver = if req.has_ver() { Some(req.get_ver()) } else { None };
            Ok(self.get_account_state_with_proof_inner(&account_address, ver))
        }).and_then(|query| {
            let mut get_resp = GetAccountStateWithProofResponse::new();
            match query {
                Some((v, a, p)) => {
                    get_resp.set_version(v);
                    get_resp.set_sparse_merkle_proof(p.into_proto());

                    match a {
                        Some(account) => {
                            get_resp.set_account_state_blob(account.into_proto());
                        }
                        _ => {}
                    }
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
            self.send_tx(signed_txn);

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
                         sink: ::grpcio::ServerStreamingSink<WatchData>) {
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
                .map(|_| info!("completed"))
                .map_err(|e| warn!("failed to reply: {:?}", e)),
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
                   sink: ::grpcio::ServerStreamingSink<WatchData>) {
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
                .map(|_| info!("completed"))
                .map_err(|e| warn!("failed to reply: {:?}", e)),
        );
    }

    fn get_transaction_by_version(&mut self, ctx: ::grpcio::RpcContext,
                                  req: GetTransactionByVersionRequest,
                                  sink: ::grpcio::UnarySink<GetTransactionResponse>) {
        let mut resp = GetTransactionResponse::new();
        let signed_tx = self.get_transaction_by_ver(req.get_ver());
        match signed_tx {
            Ok(tx) => {
                resp.set_signed_tx(tx.into_proto())
            }
            Err(err) => {
                warn!("{:?}", err);
            }
        }
        provide_grpc_response(Ok(resp), ctx, sink);
    }

    fn get_transaction_by_seq_num(&mut self, ctx: ::grpcio::RpcContext,
                                  req: GetTransactionBySeqNumRequest,
                                  sink: ::grpcio::UnarySink<GetTransactionResponse>) {
        let mut resp = GetTransactionResponse::new();
        AccountAddress::try_from(req.get_address().to_vec()).and_then(|address| -> Result<SignedTransaction> {
            self.get_transaction_by_seq_num_inner(address, req.get_seq_num())
        }).and_then(|signed_tx| {
            resp.set_signed_tx(signed_tx.into_proto());
            Ok(())
        });
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
    use state_cache::state_cache::StateCache;

    #[test]
    fn test_genesis() {
        let genesis_checked_txn = encode_genesis_transaction(&GENESIS_KEYPAIR.0, GENESIS_KEYPAIR.1.clone());
        let genesis_txn = genesis_checked_txn.into_inner();
        println!("{:?}", genesis_txn);
    }

    #[test]
    fn test_chain_service() {
        let mut rt = Runtime::new().unwrap();
        let exe = rt.executor();
        let (chain_service, _) = ChainService::new(&exe, &Some("/tmp/data".to_string()));
//        let print_future = async move {
//            let ten_millis = time::Duration::from_millis(100);
//            thread::sleep(ten_millis);
        let root = chain_service.latest_state_root_inner();
//        let ver = chain_service.get_latest_version();
        println!("{:?}", root);
//        };
//        rt.block_on(print_future.boxed().unit_error().compat()).unwrap();
    }

    #[test]
    fn test_apply_program() {
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

        let mut rt = Runtime::new().unwrap();
        let exe = rt.executor();
        let (mut chain_service, _) = ChainService::new(&exe, &Some("/tmp/data".to_string()));

        let s_n = StateCache::sequence_number_by_version(&chain_service.state_view, chain_service.state_view.latest_version().expect("latest version is none."), &account_address).unwrap();
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
        let exe = rt.executor();
        let (mut chain_service, _) = ChainService::new(&exe, &Some("/tmp/data".to_string()));
        let receiver = AccountAddress::random();
        chain_service.faucet_inner(receiver, 100);
        chain_service.faucet_inner(receiver, 100);
        let exist_flag = StateCache::exist_account(&chain_service.state_view, chain_service.state_view.latest_version().unwrap(), &receiver);
        assert_eq!(exist_flag, true);
        let ver = chain_service.get_latest_version();
        println!("{:?}", ver);
    }

    #[test]
    fn test_account_state_proof() {
        let mut rt = Runtime::new().unwrap();
        let exe = rt.executor();
        let (mut chain_service, _) = ChainService::new(&exe, &Some("/tmp/data".to_string()));
        let mut query_addr: AccountAddress = AccountAddress::random();
        for i in 1..10 {
            let receiver = AccountAddress::random();
            if i == 5 {
                query_addr = receiver.clone();
            }
            chain_service.faucet_inner(receiver, 100);
        }

        let proof = chain_service.get_account_state_with_proof_inner(&query_addr, Some(8));
        match proof {
            Some((v, a, b)) => {
                println!("{:?}", query_addr.hash());
                println!("{:?}", b);
            }
            None => {}
        }
    }
}
