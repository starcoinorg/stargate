use crate::{client_proxy::ClientProxy, commands::*};
use state_storage::AccountState;

/// Major command for account related operations.
pub struct AccountCommand {}

impl Command for AccountCommand {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["account", "a"]
    }
    fn get_description(&self) -> &'static str {
        "Account operations"
    }
    fn execute(&self, client: &mut ClientProxy, params: &[&str]) {
        let commands: Vec<Box<dyn Command>> = vec![
            Box::new(AccountCommandCreate {}),
            Box::new(AccountCommandMint {}),
            Box::new(AccountCommandState {}),
        ];

        subcommand_execute(&params[0], commands, client, &params[1..]);
    }
}

/// Sub command to create a random account. The account will not be saved on chain.
pub struct AccountCommandCreate {}

impl Command for AccountCommandCreate {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["create", "c"]
    }
    fn get_description(&self) -> &'static str {
        "Create an account. Returns reference ID to use in other operations"
    }
    fn execute(&self, client: &mut ClientProxy, _params: &[&str]) {
        println!(">> Creating/retrieving next account from wallet");
        match client.get_account() {
            Ok(addr) => println!(
                "Created/retrieved address {}",
                hex::encode(addr)
            ),
            Err(e) => report_error("Error creating account", e),
        }
    }
}

pub struct AccountCommandMint {}

impl Command for AccountCommandMint {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["mint", "mintb", "m", "mb"]
    }
    fn get_params_help(&self) -> &'static str {
        "<receiver_account_ref_id>|<receiver_account_address> <number_of_coins>"
    }
    fn get_description(&self) -> &'static str {
        "Mint coins to the account. Suffix 'b' is for blocking"
    }
    fn execute(&self, client: &mut ClientProxy, params: &[&str]) {
        if params.len() < 2 {
            println!("Invalid number of arguments for mint");
        }
        match client.faucet(params[1].parse::<u64>().unwrap()) {
            Ok(result) => println!(
                "mint success"),
            Err(e) => report_error("Error mint account", e),

        }
    }
}

pub struct AccountCommandState {}

impl Command for AccountCommandState {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["state", "s",]
    }
    fn get_params_help(&self) -> &'static str {
        ""
    }
    fn get_description(&self) -> &'static str {
        "get state of account"
    }
    fn execute(&self, client: &mut ClientProxy, params: &[&str]) {
        if params.len() != 1 {
            println!("Invalid number of arguments for state");
        }
        match client.account_state(){
            Ok(result) => {
                match result{
                    Some(data) => {
                        let account_resource=AccountState::from_account_state_blob(data).unwrap().get_account_resource();
                        match account_resource {
                            Some(resource) => {
                                println!("account state is {:?}",resource);
                            },
                            None=>{
                                println!("no such account state ");
                            },
                        }
                    },
                    None=>{
                        println!("no such account state ");
                    },
                }
            },
            Err(e) => report_error("Error mint account", e),

        }
    }
}
