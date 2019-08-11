use std::convert::TryFrom;
use std::sync::Arc;

use atomic_refcell::AtomicRefCell;
use protobuf::Message;

use chain_client::{ChainClient, RpcChainClient};
use crypto::hash::CryptoHash;
use failure::_core::cell::RefCell;
use failure::prelude::*;
use local_state_storage::LocalStateStorage;
use local_vm::LocalVM;
use nextgen_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use nextgen_crypto::SigningKey;
use nextgen_crypto::test_utils::KeyPair;
use star_types::{account_resource_ext, channel::SgChannelStream, transaction_output_helper};
use star_types::offchain_transaction::{
    OffChainTransaction, SignOffChainTransaction, TransactionOutputSigner,
};
use star_types::resource::Resource;
use types::account_address::AccountAddress;
use types::account_config::{account_resource_path, AccountResource, coin_struct_tag};
use types::language_storage::StructTag;
use types::transaction::{Program, RawTransaction, RawTransactionBytes, SignedTransaction, TransactionOutput, TransactionStatus};
use types::transaction_helpers::TransactionSigner;
use types::vm_error::*;

pub struct Wallet<C>
    where
        C: ChainClient,
{
    account_address: AccountAddress,
    keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
    client: Arc<C>,
    storage: Arc<AtomicRefCell<LocalStateStorage<C>>>,
    vm: LocalVM<LocalStateStorage<C>>,
}

impl<C> Wallet<C>
    where
        C: ChainClient,
{
    const TXN_EXPIRATION: i64 = 1000 * 60;
    const MAX_GAS_AMOUNT: u64 = 1000000;
    const GAS_UNIT_PRICE: u64 = 1;

    pub fn new(
        account_address: AccountAddress,
        keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
        rpc_host: &str,
        rpc_port: u32,
    ) -> Result<Wallet<RpcChainClient>> {
        let client = Arc::new(RpcChainClient::new(rpc_host, rpc_port));
        Wallet::new_with_client(account_address, keypair, client)
    }

    pub fn new_with_client(
        account_address: AccountAddress,
        keypair: KeyPair<Ed25519PrivateKey, Ed25519PublicKey>,
        client: Arc<C>,
    ) -> Result<Self> {
        let storage = Arc::new(AtomicRefCell::new(LocalStateStorage::new(account_address, client.clone())?));
        let vm = LocalVM::new(storage.clone());
        Ok(Self {
            account_address,
            keypair,
            client,
            storage,
            vm,
        })
    }

    pub fn execute_transaction(&self, transaction: SignedTransaction) -> TransactionOutput {
        self.vm.execute_transaction(transaction)
    }

    pub fn validate_transaction(&self, transaction: SignedTransaction) -> Option<VMStatus> {
        self.vm.validate_transaction(transaction)
    }

    pub fn get_resources() -> Vec<Resource> {
        unimplemented!()
    }

    pub fn transfer(&self, coin_resource_tag: StructTag, receiver_address: AccountAddress, amount: u64) -> Result<OffChainTransaction> {
        let program = if coin_resource_tag == coin_struct_tag() {
            vm_genesis::encode_transfer_program(&receiver_address, amount)
        } else {
            bail!("unsupported coin resource: {:#?}", coin_resource_tag)
        };
        let txn = self.create_signed_txn(program)?;
        let output = self.execute_transaction(txn.clone());
        match output.status() {
            TransactionStatus::Discard(vm_status) => bail!("transaction execute fail for: {:#?}", vm_status),
            _ => {
                //continue
            }
        };
        let output_signature = self.sign_txn_output(&output)?;
        Ok(OffChainTransaction::new(txn, receiver_address, output, output_signature))
    }

    pub fn apply_txn(&mut self, txn: &OffChainTransaction) -> Result<()> {
        //TODO verify signature
        self.storage.borrow_mut().apply_txn(txn);
        Ok(())
    }

    pub fn get(&self, path: &Vec<u8>) -> Option<Vec<u8>> {
        self.storage.borrow().get_by_path(path)
    }

    pub fn account_resource(&self) -> AccountResource {
        // account_resource must exist.
        self.get(&account_resource_path())
            .and_then(|value| account_resource_ext::from_bytes(&value).ok())
            .unwrap()
    }

    pub fn sequence_number(&self) -> u64 {
        self.account_resource().sequence_number()
    }

    pub fn balance(&self) -> u64 {
        self.account_resource().balance()
    }

    /// Craft a transaction request.
    pub fn create_signed_txn(
        &self,
        program: Program,
    ) -> Result<SignedTransaction> {
        types::transaction_helpers::create_signed_txn(
            self,
            program,
            self.account_address,
            self.sequence_number(),
            Self::MAX_GAS_AMOUNT,
            Self::GAS_UNIT_PRICE,
            Self::TXN_EXPIRATION,
        )
    }

    pub fn get_address(&self)->AccountAddress{
        self.account_address
    }
}

impl<C> TransactionSigner for Wallet<C>
    where
        C: ChainClient,
{
    fn sign_txn(&self, raw_txn: RawTransaction) -> Result<SignedTransaction> {
        assert_eq!(self.account_address, raw_txn.sender());
        self.keypair.sign_txn(raw_txn)
    }
}

impl<C> TransactionOutputSigner for Wallet<C>
    where
        C: ChainClient,
{
    fn sign_txn_output(&self, txn_output: &TransactionOutput) -> Result<Ed25519Signature> {
        let bytes = transaction_output_helper::into_pb(txn_output.clone()).unwrap().write_to_bytes()?;
        //TODO use another hash.
        let hash = RawTransactionBytes(&bytes).hash();
        let signature = self.keypair.private_key.sign_message(&hash);
        Ok(signature)
    }
}
