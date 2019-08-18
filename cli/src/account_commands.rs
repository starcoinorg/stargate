use crate::{client_proxy::ClientProxy, commands::*};

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
            //Box::new(AccountCommandListAccounts {}),
            Box::new(AccountCommandMint {}),
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
        if params.len() != 1 {
            println!("Invalid number of arguments for mint");
        }
        client.faucet(params[0].parse::<u64>().unwrap());
        // println!(">> Minting coins");
        // let is_blocking = blocking_cmd(params[0]);
        // match client.mint_coins(&params, is_blocking) {
        //     Ok(_) => {
        //         if is_blocking {
        //             println!("Finished minting!");
        //         } else {
        //             // If this value is updated, it must also be changed in
        //             // setup_scripts/docker/mint/server.py
        //             println!("Mint request submitted");
        //         }
        //     }
        //     Err(e) => report_error("Error minting coins", e),
        // }
    }
}