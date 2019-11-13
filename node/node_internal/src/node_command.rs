use crate::message_processor::MessageFuture;
use failure::prelude::*;
use futures::channel::oneshot;
use libra_types::account_address::AccountAddress;

use sgtypes::script_package::ChannelScriptPackage;

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
        responder: oneshot::Sender<Result<MessageFuture<u64>>>,
    },
    Deposit {
        receiver: AccountAddress,
        sender_amount: u64,
        receiver_amount: u64,
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
        receiver_amount: u64,
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
}
