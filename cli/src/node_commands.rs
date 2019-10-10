use crate::{client_proxy::ClientProxy, commands::*};

/// Major command for account related operations.
pub struct NodeCommand {}

impl Command for NodeCommand {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["node", "n"]
    }
    fn get_description(&self) -> &'static str {
        "Node operations"
    }
    fn execute(&self, client: &mut ClientProxy, params: &[&str]) {
        let commands: Vec<Box<dyn Command>> = vec![
            Box::new(NodeCommandConnect {}),
            Box::new(NodeCommandOpenChannel {}),
            Box::new(NodeCommandPay {}),
            Box::new(NodeCommandWithdrawChannel {}),
            Box::new(NodeCommandChannelBalance {}),
            Box::new(NodeCommandDepositChannel {}),
        ];

        subcommand_execute(&params[0], commands, client, &params[1..]);
    }
}

pub struct NodeCommandConnect {}

impl Command for NodeCommandConnect {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["connect", "c"]
    }
    fn get_params_help(&self) -> &'static str {
        "<remote_addr> <remote_ip>"
    }

    fn get_description(&self) -> &'static str {
        "connect to  remote addr"
    }
    fn execute(&self, client: &mut ClientProxy, params: &[&str]) {
        match client.connect(params, true) {
            Ok(result) => println!("connect success"),
            Err(e) => report_error("Error connect", e),
        }
    }
}

pub struct NodeCommandOpenChannel {}

impl Command for NodeCommandOpenChannel {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["open channel ", "oc"]
    }
    fn get_params_help(&self) -> &'static str {
        "<remote_addr> <local_amount> <remote_amount>"
    }
    fn get_description(&self) -> &'static str {
        "open channel with remote addr"
    }
    fn execute(&self, client: &mut ClientProxy, params: &[&str]) {
        match client.open_channel(params, true) {
            Ok(result) => println!("open channel success"),
            Err(e) => report_error("Error open channel", e),
        }
    }
}

pub struct NodeCommandDepositChannel {}

impl Command for NodeCommandDepositChannel {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["deposit", "d"]
    }
    fn get_params_help(&self) -> &'static str {
        "<remote_addr> <local_amount> <remote_amount>"
    }
    fn get_description(&self) -> &'static str {
        "deposit money to channel"
    }
    fn execute(&self, client: &mut ClientProxy, params: &[&str]) {
        match client.deposit(params, true) {
            Ok(result) => println!("deposit success"),
            Err(e) => report_error("Error pay account", e),
        }
    }
}

pub struct NodeCommandPay {}

impl Command for NodeCommandPay {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["pay", "p"]
    }
    fn get_description(&self) -> &'static str {
        "off chain pay"
    }
    fn get_params_help(&self) -> &'static str {
        "<remote_addr> <amount>"
    }
    fn execute(&self, client: &mut ClientProxy, params: &[&str]) {
        match client.off_chain_pay(params, true) {
            Ok(result) => println!("pay success"),
            Err(e) => report_error("Error pay account", e),
        }
    }
}

pub struct NodeCommandWithdrawChannel {}

impl Command for NodeCommandWithdrawChannel {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["withdraw", "wd"]
    }
    fn get_params_help(&self) -> &'static str {
        "<remote_addr> <local_amount> <remote_amount>"
    }
    fn get_description(&self) -> &'static str {
        "withdraw money from channel"
    }
    fn execute(&self, client: &mut ClientProxy, params: &[&str]) {
        match client.withdraw(params, true) {
            Ok(result) => println!("withdraw success"),
            Err(e) => report_error("Error pay account", e),
        }
    }
}

pub struct NodeCommandChannelBalance {}

impl Command for NodeCommandChannelBalance {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["channel balance ", "cb"]
    }
    fn get_description(&self) -> &'static str {
        "get balance of channel"
    }
    fn get_params_help(&self) -> &'static str {
        "<remote_addr>"
    }
    fn execute(&self, client: &mut ClientProxy, params: &[&str]) {
        match client.channel_balance(params, true) {
            Ok(result) => println!("balance is {}", result.balance),
            Err(e) => report_error("Error pay account", e),
        }
    }
}
