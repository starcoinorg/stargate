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
            Box::new(NodeCommandCloseChannel{}),
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
    fn execute(&self, client: &mut ClientProxy, _params: &[&str]) {
        println!(">> Open channel with remote addr");
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

pub struct NodeCommandCloseChannel {}

impl Command for NodeCommandCloseChannel {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["close channel ", "cc"]
    }
    fn get_description(&self) -> &'static str {
        "close channel with remote addr"
    }
    fn execute(&self, client: &mut ClientProxy, _params: &[&str]) {
        println!(">> Close channel with remote addr");
    }
}
