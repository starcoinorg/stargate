// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use cli::{client_proxy::ClientProxy, commands::*};
use libra_logger::set_default_global_logger;
use rustyline::{config::CompletionType, error::ReadlineError, Config, Editor};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Libra Client",
    author = "The Libra Association",
    about = "Libra client to connect to a specific validator"
)]
struct Args {
    /// Admission Control port to connect to.
    #[structopt(short = "p", long = "port", default_value = "30307")]
    pub port: u16,
    /// Host address/name to connect to.
    #[structopt(short = "a", long = "host")]
    pub host: String,
    /// Chain Host address/name to connect to.
    #[structopt(short = "s", long = "chain_host", default_value = "127.0.0.1")]
    pub chain_host: String,
    /// Chain port to connect to.
    #[structopt(short = "r", long = "chain_port", default_value = "3000")]
    pub chain_port: u16,
    /// Path to the generated keypair for the faucet account. The faucet account can be used to
    /// mint coins. If not passed, a new keypair will be generated for
    /// you and placed in a temporary directory.
    /// To manually generate a keypair, use generate_keypair:
    /// `cargo run -p generate_keypair -- -o <output_file_path>`
    #[structopt(
        short = "m",
        long = "faucet_key_file_path",
        default_value = "wallet/key"
    )]
    pub faucet_account_file: String,
}

fn main() -> std::io::Result<()> {
    let _logger = set_default_global_logger(false /* async */, None);

    let (commands, alias_to_cmd) = get_commands();

    let args = Args::from_args();
    //let faucet_account_file = args.faucet_account_file.unwrap_or_else(|| "".to_string());

    let mut client_proxy = ClientProxy::new(
        &args.host,
        args.port,
        &args.chain_host,
        args.chain_port,
        &args.faucet_account_file,
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, &format!("{}", e)[..]))?;

    let cli_info = format!("Connected to validator at: {}:{}", args.host, args.port);
    print_help(&cli_info, &commands);
    println!("Please, input commands: \n");

    let config = Config::builder()
        .history_ignore_space(true)
        .completion_type(CompletionType::List)
        .auto_add_history(true)
        .build();
    let mut rl = Editor::<()>::with_config(config);
    loop {
        let readline = rl.readline("sg% ");
        match readline {
            Ok(line) => {
                let params = parse_cmd(&line);
                match alias_to_cmd.get(params[0]) {
                    Some(cmd) => cmd.execute(&mut client_proxy, &params),
                    None => match params[0] {
                        "quit" | "q!" => break,
                        "help" | "h" => print_help(&cli_info, &commands),
                        "" => continue,
                        x => println!("Unknown command: {:?}", x),
                    },
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }

    Ok(())
}

fn print_help(client_info: &str, commands: &[std::sync::Arc<dyn Command>]) {
    println!("{}", client_info);
    println!("usage: <command> <args>\n\nUse the following commands:\n");
    for cmd in commands {
        println!(
            "{} {}\n\t{}",
            cmd.get_aliases().join(" | "),
            cmd.get_params_help(),
            cmd.get_description()
        );
    }

    println!("help | h \n\tPrints this help");
    println!("quit | q! \n\tExit this client");
    println!("\n");
}
