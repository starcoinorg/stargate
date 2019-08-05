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
            Box::new(NodeCommandOpenChannel {}),
            Box::new(NodeCommandPay {}),
            Box::new(NodeCommandCloseChannel{}),
        ];

        subcommand_execute(&params[0], commands, client, &params[1..]);
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
        vec!["open channel ", "oc"]
    }
    fn get_description(&self) -> &'static str {
        "open channel with remote addr"
    }
    fn execute(&self, client: &mut ClientProxy, _params: &[&str]) {
        println!(">> pay to remote addr");
    }
}

pub struct NodeCommandCloseChannel {}

impl Command for NodeCommandCloseChannel {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["open channel ", "oc"]
    }
    fn get_description(&self) -> &'static str {
        "open channel with remote addr"
    }
    fn execute(&self, client: &mut ClientProxy, _params: &[&str]) {
        println!(">> Close channel with remote addr");
    }
}
