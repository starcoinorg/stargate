extern crate types;

use chain_proto::proto::chain_grpc::Chain;
use chain_proto::proto::chain::{LeastRootRequest, LeastRootResponse,
                                FaucetRequest, FaucetResponse,
                                GetAccountStateWithProofByStateRootRequest, GetAccountStateWithProofByStateRootResponse,
                                WatchTransactionRequest, WatchTransactionResponse,
                                SubmitTransactionRequest, SubmitTransactionResponse,
                                StateByAccessPathResponse};
use types::proto::{access_path::AccessPath};
use types::{transaction::{SignedTransaction, RawTransaction, TransactionPayload}, write_set::{WriteOp, WriteSet}, account_address::AccountAddress};
use proto_conv::FromProto;
use futures::sync::mpsc::{unbounded, UnboundedSender, UnboundedReceiver, SendError};
use super::pub_sub;
use hex;
use futures::MapErr;
use futures::future::Future;
use futures::stream::Stream;
use futures::*;
use grpcio::WriteFlags;
use state_storage::{StateStorage, AccountState};
use scratchpad::SparseMerkleTree;
use super::transaction_storage::TransactionStorage;
use core::borrow::{BorrowMut, Borrow};
use std::sync::{Arc, RwLock, Mutex};
use std::rc::Rc;
use self::types::transaction::{TransactionInfo, Version};
use std::cell::RefCell;
use crypto::{hash::CryptoHash, HashValue};
use grpc_helpers::provide_grpc_response;
use std::{thread, fs::File, io::prelude::*, path::PathBuf};
use protobuf::parse_from_bytes;
use vm_genesis::{encode_genesis_transaction, GENESIS_KEYPAIR};
use ed25519_dalek::PublicKey;
use tiny_keccak::Keccak;
use std::convert::TryFrom;

#[derive(Clone)]
pub struct ChainService {
    sender: UnboundedSender<SignedTransaction>,
    state_db: Arc<Mutex<StateStorage>>,
    tx_db: Arc<Mutex<TransactionStorage>>,
}

impl ChainService {
    pub fn new() -> Self {
        let (sender, mut receiver) = unbounded::<SignedTransaction>();
        let tx_db = Arc::new(Mutex::new(TransactionStorage::new()));
        let state_db = Arc::new(Mutex::new(StateStorage::new()));
        let chain_service = ChainService { sender: sender.clone(), state_db, tx_db };
        let chain_service_clone = chain_service.clone();
        thread::spawn(move || {
            loop {
                while let msg = receiver.poll() {
                    match msg {
                        Ok(async_result) => {
                            match async_result {
                                Async::Ready(option_result) => {
                                    match option_result {
                                        Some(tx) => {
                                            chain_service_clone.submit_transaction_real(tx);
                                        }
                                        _ => {}
                                    }
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
            }
        });

        //let genesis_txn = genesis_transaction();
        let genesis_checked_txn = encode_genesis_transaction(&GENESIS_KEYPAIR.0, GENESIS_KEYPAIR.1.clone());
        let genesis_txn = genesis_checked_txn.into_inner();
        sender.unbounded_send(genesis_txn).unwrap();

        chain_service
    }

    fn submit_transaction_real(&self, sign_tx: SignedTransaction) {
        let signed_tx_hash = sign_tx.clone().hash();
        let mut tx_db = self.tx_db.lock().unwrap();
        let exist_flag = tx_db.exist_signed_transaction(signed_tx_hash);
        if exist_flag {
            // 1. state_root
            let payload = sign_tx.payload().clone();
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
                TransactionPayload::Program(_p) => {
                    panic!("Program Payload Err")
                }
            }
        }
    }

    pub fn submit_transaction_inner(&self, sign_tx: SignedTransaction) {
        self.sender.unbounded_send(sign_tx).unwrap();
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
}

//pub fn genesis_transaction() -> SignedTransaction {
//    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
//    path.pop();
//    path.push("chain_service/genesis.blob");
//
//    let mut f = File::open(&path).unwrap();
//    let mut bytes = vec![];
//    f.read_to_end(&mut bytes).unwrap();
//    let txn = SignedTransaction::from_proto(parse_from_bytes(&bytes).unwrap()).unwrap();
//    println!("{:?}", txn);
//    txn
//}
//
//pub fn genesis_write_set(txn: SignedTransaction) -> WriteSet {
//    let GENESIS_WRITE_SET: WriteSet = {
//        match txn.payload() {
//            TransactionPayload::WriteSet(ws) => ws.clone(),
//            _ => panic!("Expected writeset txn in genesis txn"),
//        }
//    };
//
//    GENESIS_WRITE_SET
//}

impl Chain for ChainService {
    fn least_state_root(&mut self, ctx: ::grpcio::RpcContext, req: LeastRootRequest, sink: ::grpcio::UnarySink<LeastRootResponse>) {
        let least_hash_root = self.least_state_root_inner();
        let mut resp = LeastRootResponse::new();
        resp.set_state_root_hash(least_hash_root.to_vec());
        provide_grpc_response(Ok(resp), ctx, sink);
    }

    fn faucet(&mut self, ctx: ::grpcio::RpcContext,
              req: FaucetRequest,
              sink: ::grpcio::UnarySink<FaucetResponse>) {
        let mut state_db = self.state_db.lock().unwrap();
        let account_address = AccountAddress::try_from(req.address.to_vec());
        match account_address {
            Ok(account) => {
                let account_state = state_db.get_account_state(&account);
                match account_state {
                    Some(a_s) => {}
                    _ => {
                        state_db.create_account(account);
                    }
                }

                //TODO
            }
            _ => {}
        }


//        let a = SignedTransaction

//        let a = RawTransaction::new();
        unimplemented!()
    }

    fn get_account_state_with_proof_by_state_root(&mut self, ctx: ::grpcio::RpcContext,
                                                  req: GetAccountStateWithProofByStateRootRequest,
                                                  sink: ::grpcio::UnarySink<GetAccountStateWithProofByStateRootResponse>) {
        let account_address = AccountAddress::try_from(req.address.to_vec()).unwrap();
        let state_db = self.state_db.lock().unwrap();
        let a_s = state_db.get_account_state(&account_address).unwrap();
        let mut resp = GetAccountStateWithProofByStateRootResponse::new();
        resp.set_account_state_blob((*a_s).to_bytes());
        provide_grpc_response(Ok(resp), ctx, sink);
    }

    fn submit_transaction(&mut self, ctx: ::grpcio::RpcContext,
                          req: SubmitTransactionRequest,
                          sink: ::grpcio::UnarySink<SubmitTransactionResponse>) {
        let signed_txn = req.signed_txn.clone().unwrap();
        let mut wt_resp = WatchTransactionResponse::new();
        wt_resp.set_signed_txn(signed_txn);
        pub_sub::send(wt_resp).unwrap();

        self.submit_transaction_inner(SignedTransaction::from_proto(req.signed_txn.unwrap()).unwrap());
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
        let account_address = AccountAddress::try_from(req.address.to_vec()).unwrap();
        let state_db = self.state_db.lock().unwrap();
        let a_s = state_db.get_account_state(&account_address).unwrap();
        let resource = a_s.get(&req.path.to_vec());
        let mut resp = StateByAccessPathResponse::new();
        match resource {
            Some(re) => {
                resp.set_resource(re);
            }
            _ => {}
        }
        provide_grpc_response(Ok(resp), ctx, sink);
    }
}

pub fn get_address(public_key: PublicKey) -> Result<AccountAddress, Box<std::error::Error>> {
    let mut keccak = Keccak::new_sha3_256();
    let mut hash = [0u8; 32];
    keccak.update(&public_key.to_bytes());
    keccak.finalize(&mut hash);
    let addr = AccountAddress::try_from(&hash[..])?;
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use vm_genesis::{encode_genesis_transaction, GENESIS_KEYPAIR};

    #[test]
    fn testGenesis() {
        let genesis_checked_txn = encode_genesis_transaction(&GENESIS_KEYPAIR.0, GENESIS_KEYPAIR.1.clone());
        let genesis_txn = genesis_checked_txn.into_inner();
        println!("{:?}", txn);
    }
}
