use crate::message_processor::MessageFuture;
use failure::prelude::*;
use futures::channel::oneshot;
use libra_types::{account_address::AccountAddress, account_config::AccountResource};

use sgtypes::script_package::ChannelScriptPackage;
use sgtypes::signed_channel_transaction::SignedChannelTransaction;

use libra_crypto::HashValue;
use node_proto::DeployModuleResponse;

pub enum NodeMessage {
    Execute {
        receiver_address: AccountAddress,
        package_name: String,
        script_name: String,
        transaction_args: Vec<Vec<u8>>,
        responder: oneshot::Sender<Result<MessageFuture<u64>>>,
    },
    Install {
        channel_script_package: ChannelScriptPackage,
        responder: oneshot::Sender<Result<()>>,
    },
    Deposit {
        receiver: AccountAddress,
        sender_amount: u64,
        responder: oneshot::Sender<Result<MessageFuture<u64>>>,
    },
    OpenChannel {
        receiver: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
        responder: oneshot::Sender<Result<MessageFuture<u64>>>,
    },
    Withdraw {
        receiver: AccountAddress,
        sender_amount: u64,
        responder: oneshot::Sender<Result<MessageFuture<u64>>>,
    },
    ChannelPay {
        receiver_address: AccountAddress,
        amount: u64,
        responder: oneshot::Sender<Result<MessageFuture<u64>>>,
    },
    ChannelBalance {
        participant: AccountAddress,
        responder: oneshot::Sender<Result<u64>>,
    },
    DeployModule {
        module_code: Vec<u8>,
        responder: oneshot::Sender<Result<DeployModuleResponse>>,
    },
    ChainBalance {
        responder: oneshot::Sender<Result<AccountResource>>,
    },
    TxnBySn {
        participant_address: AccountAddress,
        channel_seq_number: u64,
        responder: oneshot::Sender<Result<SignedChannelTransaction>>,
    },
    SetTimeout {
        default_future_timeout: u64,
    },
    ChannelTransactionProposal {
        participant_address: AccountAddress,
        transaction_hash: HashValue,
        approve: bool,
        responder: oneshot::Sender<Result<MessageFuture<u64>>>,
    },
}
