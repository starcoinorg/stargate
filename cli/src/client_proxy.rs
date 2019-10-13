use crate::{commands::*, AccountData, AccountStatus};

use canonical_serialization::{CanonicalSerialize, CanonicalSerializer, SimpleSerializer};
use cli_wallet::cli_wallet::WalletLibrary;
use failure::prelude::*;
use grpcio::EnvBuilder;
use node_client::NodeClient;
use node_proto::{
    ChannelBalanceRequest, ChannelBalanceResponse, ConnectRequest, ConnectResponse,
    DeployModuleRequest, DeployModuleResponse, DepositRequest, DepositResponse,
    ExecuteScriptRequest, InstallChannelScriptPackageRequest, OpenChannelRequest,
    OpenChannelResponse, PayRequest, PayResponse, WithdrawRequest, WithdrawResponse,
};
use sgchain::{
    client_state_view::ClientStateView,
    star_chain_client::{faucet_sync, ChainClient, StarChainClient},
};
use sgcompiler::{Compiler, StateViewModuleLoader};
use star_types::script_package::ChannelScriptPackage;
use std::{
    fs,
    io::{stdout, Write},
    path::Path,
    process::Command,
    sync::Arc,
    thread, time,
};
use tempfile::{NamedTempFile, TempPath};
use types::{
    account_address::AccountAddress,
    proof::SparseMerkleProof,
    transaction::{
        parse_as_transaction_argument, Program, Script, SignedTransaction, TransactionPayload,
        Version,
    },
    transaction_helpers::{create_signed_txn, TransactionSigner},
};

const GAS_UNIT_PRICE: u64 = 0;
const MAX_GAS_AMOUNT: u64 = 100_000;
const TX_EXPIRATION: i64 = 100;

pub struct ClientProxy {
    node_client: NodeClient,
    wallet: WalletLibrary,
    chain_client: StarChainClient,
    temp_files: Vec<TempPath>,
}

impl ClientProxy {
    /// Construct a new TestClient.
    pub fn new(
        host: &str,
        port: u16,
        chain_host: &str,
        chain_port: u16,
        faucet_account_file: &str,
    ) -> Result<Self> {
        let env_builder_arc = Arc::new(EnvBuilder::new().build());
        let node_client = NodeClient::new(env_builder_arc, host, port);
        let chain_client = StarChainClient::new(chain_host, chain_port as u32);
        Ok(ClientProxy {
            node_client,
            wallet: WalletLibrary::new(faucet_account_file),
            chain_client,
            temp_files: vec![],
        })
    }

    pub fn get_account(&mut self) -> Result<AccountAddress> {
        Ok(self.wallet.get_address())
    }

    pub fn faucet(&mut self, amount: u64) -> Result<()> {
        faucet_sync(self.chain_client.clone(), self.wallet.get_address(), amount)
    }

    pub fn open_channel(
        &mut self,
        space_delim_strings: &[&str],
        is_blocking: bool,
    ) -> Result<OpenChannelResponse> {
        ensure!(
            space_delim_strings.len() == 4,
            "Invalid number of arguments for open channel"
        );
        let response = self.node_client.open_channel(OpenChannelRequest {
            remote_addr: AccountAddress::from_hex_literal(space_delim_strings[1])?,
            local_amount: space_delim_strings[2].parse::<u64>()?,
            remote_amount: space_delim_strings[3].parse::<u64>()?,
        })?;
        Ok(response)
    }

    pub fn withdraw(
        &mut self,
        space_delim_strings: &[&str],
        is_blocking: bool,
    ) -> Result<WithdrawResponse> {
        ensure!(
            space_delim_strings.len() == 4,
            "Invalid number of arguments for withdraw"
        );
        let response = self.node_client.withdraw(WithdrawRequest {
            remote_addr: AccountAddress::from_hex_literal(space_delim_strings[1])?,
            local_amount: space_delim_strings[2].parse::<u64>()?,
            remote_amount: space_delim_strings[3].parse::<u64>()?,
        })?;
        Ok(response)
    }

    pub fn deposit(
        &mut self,
        space_delim_strings: &[&str],
        is_blocking: bool,
    ) -> Result<DepositResponse> {
        ensure!(
            space_delim_strings.len() == 4,
            "Invalid number of arguments for deposit"
        );
        let response = self.node_client.deposit(DepositRequest {
            remote_addr: AccountAddress::from_hex_literal(space_delim_strings[1])?,
            local_amount: space_delim_strings[2].parse::<u64>()?,
            remote_amount: space_delim_strings[3].parse::<u64>()?,
        })?;
        Ok(response)
    }

    pub fn off_chain_pay(
        &mut self,
        space_delim_strings: &[&str],
        _is_blocking: bool,
    ) -> Result<PayResponse> {
        ensure!(
            space_delim_strings.len() == 3,
            "Invalid number of arguments for offchain pay"
        );
        let response = self.node_client.pay(PayRequest {
            remote_addr: AccountAddress::from_hex_literal(space_delim_strings[1])?,
            amount: space_delim_strings[2].parse::<u64>()?,
        })?;
        Ok(response)
    }

    pub fn connect(
        &mut self,
        space_delim_strings: &[&str],
        is_blocking: bool,
    ) -> Result<ConnectResponse> {
        ensure!(
            space_delim_strings.len() == 3,
            "Invalid number of arguments for connect"
        );
        let response = self.node_client.connect(ConnectRequest {
            remote_addr: AccountAddress::from_hex_literal(space_delim_strings[1])?,
            remote_ip: space_delim_strings[2].to_string(),
        })?;
        Ok(response)
    }

    pub fn channel_balance(
        &mut self,
        space_delim_strings: &[&str],
        is_blocking: bool,
    ) -> Result<ChannelBalanceResponse> {
        ensure!(
            space_delim_strings.len() == 2,
            "Invalid number of arguments for channel balance"
        );
        let response = self.node_client.channel_balance(ChannelBalanceRequest {
            remote_addr: AccountAddress::from_hex_literal(space_delim_strings[1])?,
        })?;
        Ok(response)
    }

    pub fn account_state(&mut self) -> Result<(Version, Option<Vec<u8>>, SparseMerkleProof)> {
        Ok(self
            .chain_client
            .get_account_state_with_proof(&self.wallet.get_address(), None)?)
    }

    /// Compile move program
    pub fn compile_program(&mut self, space_delim_strings: &[&str]) -> Result<String> {
        let file_path = space_delim_strings[1];
        let is_module = match space_delim_strings[2] {
            "module" => true,
            "script" => false,
            _ => bail!(
                "Invalid program type: {}. Available options: module, script",
                space_delim_strings[3]
            ),
        };
        let output_path = {
            if space_delim_strings.len() == 4 {
                space_delim_strings[3].to_string()
            } else {
                let tmp_path = NamedTempFile::new()?.into_temp_path();
                let path = tmp_path.to_str().unwrap().to_string();
                self.temp_files.push(tmp_path);
                path
            }
        };

        let tmp_source_path = NamedTempFile::new()?;
        let mut tmp_source_file = std::fs::File::create(tmp_source_path.as_ref())?;
        let mut code = fs::read_to_string(file_path)?;
        code = code.replace("{{sender}}", &format!("0x{}", self.wallet.get_address()));
        writeln!(tmp_source_file, "{}", code)?;

        let mut args = format!(
            "run -p compiler -- {} -a {} -o {}{}",
            tmp_source_path.path().display(),
            self.wallet.get_address(),
            output_path,
            if is_module { " -m" } else { "" },
        );

        let status = Command::new("cargo")
            .args(args.split(' '))
            .spawn()?
            .wait()?;
        if !status.success() {
            return Err(format_err!("compilation failed"));
        }

        Ok(output_path)
    }

    fn submit_program(
        &mut self,
        space_delim_strings: &[&str],
        program: TransactionPayload,
    ) -> Result<()> {
        let addr = self.wallet.get_address();
        let sequence_number = self
            .chain_client
            .account_sequence_number(&addr)
            .expect("should have seq number");

        let txn = self.create_submit_transaction(program, sequence_number, None, None)?;

        self.chain_client.submit_signed_transaction(txn)?;

        self.wait_for_transaction(&addr, sequence_number);

        Ok(())
    }

    /// Publish move module
    pub fn publish_module(&mut self, space_delim_strings: &[&str]) -> Result<()> {
        let program = serde_json::from_slice(&fs::read(space_delim_strings[1])?)?;
        self.submit_program(space_delim_strings, TransactionPayload::Module(program))
    }

    /// Execute custom script
    pub fn execute_script(&mut self, space_delim_strings: &[&str]) -> Result<()> {
        let script: Script = serde_json::from_slice(&fs::read(space_delim_strings[1])?)?;
        let (script_bytes, _) = script.into_inner();
        let arguments: Vec<_> = space_delim_strings[2..]
            .iter()
            .filter_map(|arg| parse_as_transaction_argument(arg).ok())
            .collect();
        self.submit_program(
            space_delim_strings,
            TransactionPayload::Script(Script::new(script_bytes, arguments)),
        )
    }

    pub fn deploy_module(&mut self, space_delim_strings: &[&str]) -> Result<DeployModuleResponse> {
        let dir_path = space_delim_strings[1];

        let path = Path::new(dir_path);
        let module_source = std::fs::read_to_string(path).unwrap();

        let account = self.get_account().unwrap().clone();
        let client_state_view = ClientStateView::new(None, &self.chain_client);
        let module_loader = StateViewModuleLoader::new(&client_state_view);
        let compiler = Compiler::new_with_module_loader(account, &module_loader);
        let module_byte_code = compiler.compile_module(module_source.as_str())?;

        let response = self
            .node_client
            .deploy_module(DeployModuleRequest::new(module_byte_code))?;

        Ok(response)
    }

    pub fn install_script(&mut self, space_delim_strings: &[&str]) -> Result<()> {
        let dir_path = space_delim_strings[1];

        let path = Path::new(dir_path);
        let account = self.get_account().unwrap().clone();
        let client_state_view = ClientStateView::new(None, &self.chain_client);
        let module_loader = StateViewModuleLoader::new(&client_state_view);
        let compiler = Compiler::new_with_module_loader(account, &module_loader);

        let package = compiler.compile_package(path)?;
        self.node_client
            .install_channel_script_package(InstallChannelScriptPackageRequest::new(package))?;
        Ok(())
    }

    pub fn execute_installed_script(&mut self, space_delim_strings: &[&str]) -> Result<()> {
        let remote_addr = AccountAddress::from_hex_literal(space_delim_strings[1])?;
        let package_name = space_delim_strings[2];
        let script_name = space_delim_strings[3];

        let arguments: Vec<_> = space_delim_strings[4..]
            .iter()
            .filter_map(|arg| {
                let mut serializer = SimpleSerializer::<Vec<u8>>::new();
                let arg = parse_as_transaction_argument(arg).ok().unwrap();
                arg.serialize(&mut serializer).unwrap();
                Some(serializer.get_output())
            })
            .collect();

        let execute_request = ExecuteScriptRequest::new(
            remote_addr,
            package_name.to_string(),
            script_name.to_string(),
            arguments,
        );
        let _response = self.node_client.execute_script(execute_request)?;
        Ok(())
    }

    /// Craft a transaction request.
    fn create_submit_transaction(
        &mut self,
        program: TransactionPayload,
        seq: u64,
        max_gas_amount: Option<u64>,
        gas_unit_price: Option<u64>,
    ) -> Result<SignedTransaction> {
        let addr = self.wallet.get_address();
        return create_signed_txn(
            *Box::new(&self.wallet),
            program,
            addr,
            seq,
            max_gas_amount.unwrap_or(MAX_GAS_AMOUNT),
            gas_unit_price.unwrap_or(GAS_UNIT_PRICE),
            TX_EXPIRATION,
        );
    }

    /// Waits for the next transaction for a specific address and prints it
    pub fn wait_for_transaction(&mut self, account: &AccountAddress, sequence_number: u64) {
        let mut max_iterations = 5000;
        print!("[waiting ");
        loop {
            stdout().flush().unwrap();
            max_iterations -= 1;

            if let Ok(Some(_)) = self
                .chain_client
                .get_transaction_by_seq_num(&account, sequence_number)
            {
                println!("transaction is stored!");
                break;
            } else if max_iterations == 0 {
                panic!("wait_for_transaction timeout");
            } else {
                print!(".");
            }
            thread::sleep(time::Duration::from_millis(10));
        }
    }
}

fn parse_bool(para: &str) -> Result<bool> {
    Ok(para.to_lowercase().parse::<bool>()?)
}
