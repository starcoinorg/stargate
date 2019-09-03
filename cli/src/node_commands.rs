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
            Box::new(NodeCommandWithdrawChannel{}),
        ];

        subcommand_execute(&params[0], commands, client, &params[1..]);
    }
}

pub struct NodeCommandConnect {}

impl Command for NodeCommandConnect {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["connect", "c"]
    }
    fn get_description(&self) -> &'static str {
        "connect to  remote addr"
    }
    fn execute(&self, client: &mut ClientProxy, params: &[&str]) {
        match client.connect(params,true) {
            Ok(result) => println!(
                "connect success"),
            Err(e) => report_error("Error connect", e),

        }
    }
}

pub struct NodeCommandOpenChannel {}

impl Command for NodeCommandOpenChannel {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["open channel ", "oc"]
    }
    fn get_description(&self) -> &'static str {
        "open channel with remote addr"
    }
    fn execute(&self, client: &mut ClientProxy, params: &[&str]) {
        match client.open_channel(params,true) {
            Ok(result) => println!(
                "open channel success"),
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

    fn execute(&self, client: &mut ClientProxy, params: &[&str]) {
        match client.off_chain_pay(params,true) {
            Ok(result) => println!(
                "pay success"),
            Err(e) => report_error("Error pay account", e),

        }
    }
}

pub struct NodeCommandWithdrawChannel {}

impl Command for NodeCommandWithdrawChannel {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["withdraw", "wd"]
    }
    fn get_description(&self) -> &'static str {
        "withdraw money from channel"
    }
    fn execute(&self, client: &mut ClientProxy, params: &[&str]) {
        match client.off_chain_pay(params,true) {
            Ok(result) => println!(
                "withdraw success"),
            Err(e) => report_error("Error pay account", e),

        }
    }
}
