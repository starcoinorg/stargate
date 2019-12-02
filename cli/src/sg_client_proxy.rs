// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
use crate::commands::*;
use failure::prelude::*;
use grpcio::EnvBuilder;
use libra_crypto::HashValue;
use libra_types::{
    account_address::{AccountAddress, ADDRESS_LENGTH},
    proof::SparseMerkleProof,
    transaction::{parse_as_transaction_argument, Version},
};
use libra_wallet::key_factory::ChildNumber;
use libra_wallet::wallet_library::WalletLibrary;
use node_client::NodeClient;
use node_proto::{
    ChannelBalanceRequest, ChannelBalanceResponse, ChannelTransactionProposalRequest,
    DeployModuleRequest, DeployModuleResponse, DepositRequest, DepositResponse, EmptyResponse,
    ExecuteScriptRequest, GetChannelTransactionProposalResponse,
    InstallChannelScriptPackageRequest, OpenChannelRequest, OpenChannelResponse, PayRequest,
    PayResponse, WithdrawRequest, WithdrawResponse,
};
use sgchain::{
    client_state_view::ClientStateView,
    star_chain_client::{faucet_sync, ChainClient, StarChainClient},
};
use sgcompiler::{Compiler, StateViewModuleLoader};
use std::str::FromStr;
use std::{convert::TryFrom, fs, path::Path, sync::Arc};

/// Enum used for error formatting.
#[derive(Debug)]
enum InputType {
    Usize,
}

pub struct SGClientProxy {
    node_client: NodeClient,
    wallet: WalletLibrary,
    chain_client: StarChainClient,
}

impl SGClientProxy {
    /// Construct a new TestClient.
    pub fn new(
        host: &str,
        port: u16,
        chain_host: &str,
        chain_port: u16,
        _faucet_account_file: &str,
    ) -> Result<Self> {
        let env_builder_arc = Arc::new(EnvBuilder::new().build());
        let node_client = NodeClient::new(env_builder_arc, host, port);
        let chain_client = StarChainClient::new(chain_host, chain_port as u32);
        Ok(SGClientProxy {
            node_client,
            wallet: WalletLibrary::new(),
            chain_client,
        })
    }

    pub fn create_account(&mut self) -> Result<(AccountAddress, ChildNumber)> {
        Ok(self.wallet.new_address()?)
    }

    pub fn faucet(&mut self, amount: u64, account_str: &str) -> Result<()> {
        let address = self.get_account_address_from_parameter(account_str)?;
        faucet_sync(self.chain_client.clone(), address, amount)
    }

    pub fn open_channel(
        &mut self,
        space_delim_strings: &[&str],
        _is_blocking: bool,
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
        _is_blocking: bool,
    ) -> Result<WithdrawResponse> {
        ensure!(
            space_delim_strings.len() == 4,
            "Invalid number of arguments for withdraw"
        );
        let response = self.node_client.withdraw(WithdrawRequest {
            remote_addr: AccountAddress::from_hex_literal(space_delim_strings[1])?,
            local_amount: space_delim_strings[2].parse::<u64>()?,
        })?;
        Ok(response)
    }

    pub fn deposit(
        &mut self,
        space_delim_strings: &[&str],
        _is_blocking: bool,
    ) -> Result<DepositResponse> {
        ensure!(
            space_delim_strings.len() == 4,
            "Invalid number of arguments for deposit"
        );
        let response = self.node_client.deposit(DepositRequest {
            remote_addr: AccountAddress::from_hex_literal(space_delim_strings[1])?,
            local_amount: space_delim_strings[2].parse::<u64>()?,
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

    pub fn channel_balance(
        &mut self,
        space_delim_strings: &[&str],
        _is_blocking: bool,
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

    pub fn account_state(
        &mut self,
        account_str: &str,
    ) -> Result<(Version, Option<Vec<u8>>, SparseMerkleProof)> {
        let address = self.get_account_address_from_parameter(account_str)?;
        Ok(self
            .chain_client
            .get_account_state_with_proof(&address, None)?)
    }

    pub fn deploy_module(&mut self, space_delim_strings: &[&str]) -> Result<DeployModuleResponse> {
        let address = self.get_account_address_from_parameter(space_delim_strings[1])?;
        let dir_path = space_delim_strings[2];

        let path = Path::new(dir_path);
        let module_source = std::fs::read_to_string(path).unwrap();

        let client_state_view = ClientStateView::new(None, &self.chain_client);
        let module_loader = StateViewModuleLoader::new(&client_state_view);
        let compiler = Compiler::new_with_module_loader(address, &module_loader);
        let module_byte_code = compiler.compile_module(module_source.as_str())?;

        let response = self
            .node_client
            .deploy_module(DeployModuleRequest::new(module_byte_code))?;

        Ok(response)
    }

    pub fn install_script(&mut self, space_delim_strings: &[&str]) -> Result<()> {
        let address = self.get_account_address_from_parameter(space_delim_strings[1])?;
        let path = Path::new(space_delim_strings[2]);
        let csp_ext = "csp";
        let package;

        if path.is_file() && path.extension().unwrap() == csp_ext {
            package = serde_json::from_slice(&fs::read(path)?)?;
        } else {
            let output_path = path.with_extension(csp_ext);
            let client_state_view = ClientStateView::new(None, &self.chain_client);
            let module_loader = StateViewModuleLoader::new(&client_state_view);
            let compiler = Compiler::new_with_module_loader(address, &module_loader);

            package = compiler.compile_package_with_output(path, &output_path)?;
        }

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
                let arg = parse_as_transaction_argument(arg).ok().unwrap();
                let data = lcs::to_bytes(&arg).expect("Failed to serialize.");
                Some(data)
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

    pub fn get_channel_transaction_proposal(
        &mut self,
        space_delim_strings: &[&str],
    ) -> Result<GetChannelTransactionProposalResponse> {
        let remote_addr = AccountAddress::from_hex_literal(space_delim_strings[1])?;
        self.node_client
            .get_channel_transaction_proposal(ChannelBalanceRequest::new(remote_addr))
    }

    pub fn channel_transaction_proposal(
        &mut self,
        space_delim_strings: &[&str],
    ) -> Result<EmptyResponse> {
        let remote_addr = AccountAddress::from_hex_literal(space_delim_strings[1])?;
        let transaction_hash = from_hex_literal(space_delim_strings[2])?;
        let approve = bool::from_str(space_delim_strings[3])?;

        self.node_client
            .channel_transaction_proposal(ChannelTransactionProposalRequest::new(
                remote_addr,
                transaction_hash,
                approve,
            ))
    }

    pub fn get_account_address_from_parameter(&self, para: &str) -> Result<AccountAddress> {
        match is_address(para) {
            true => SGClientProxy::address_from_strings(para),
            false => {
                let account_ref_id = para.parse::<usize>().map_err(|error| {
                    format_parse_data_error(
                        "account_reference_id/account_address",
                        InputType::Usize,
                        para,
                        error,
                    )
                })?;
                //                let account_data = self.accounts.get(account_ref_id).ok_or_else(|| {
                //                    format_err!(
                //                        "Unable to find account by account reference id: {}, to see all existing \
                //                         accounts, run: 'account list'",
                //                        account_ref_id
                //                    )
                //                })?;
                Ok(self
                    .wallet
                    .get_addresses()?
                    .get(account_ref_id)
                    .unwrap()
                    .clone())
            }
        }
    }

    fn address_from_strings(data: &str) -> Result<AccountAddress> {
        let account_vec: Vec<u8> = hex::decode(data.parse::<String>()?)?;
        ensure!(
            account_vec.len() == ADDRESS_LENGTH,
            "The address {:?} is of invalid length. Addresses must be 32-bytes long"
        );
        let account = AccountAddress::try_from(&account_vec[..]).map_err(|error| {
            format_err!(
                "The address {:?} is invalid, error: {:?}",
                &account_vec,
                error,
            )
        })?;
        Ok(account)
    }

    /// Write mnemonic recover to the file specified.
    pub fn write_recovery(&self, space_delim_strings: &[&str]) -> Result<()> {
        ensure!(
            space_delim_strings.len() == 2,
            "Invalid number of arguments for writing recovery"
        );

        self.wallet
            .write_recovery(&Path::new(space_delim_strings[1]))?;
        Ok(())
    }

    /// Recover wallet accounts from file and return vec<(account_address, index)>.
    pub fn recover_wallet_accounts(
        &mut self,
        space_delim_strings: &[&str],
    ) -> Result<Vec<AccountAddress>> {
        ensure!(
            space_delim_strings.len() == 2,
            "Invalid number of arguments for recovering wallets"
        );

        let wallet = WalletLibrary::recover(&Path::new(space_delim_strings[1]))?;
        let address_list = wallet.get_addresses()?;
        self.wallet = wallet;
        Ok(address_list)
    }
}

fn _parse_bool(para: &str) -> Result<bool> {
    Ok(para.to_lowercase().parse::<bool>()?)
}

fn format_parse_data_error<T: std::fmt::Debug>(
    field: &str,
    input_type: InputType,
    value: &str,
    error: T,
) -> Error {
    format_err!(
        "Unable to parse input for {} - \
         please enter an {:?}.  Input was: {}, error: {:?}",
        field,
        input_type,
        value,
        error
    )
}

fn from_hex_literal(literal: &str) -> Result<HashValue> {
    let mut hex_string = String::from(&literal[2..]);
    if hex_string.len() % 2 != 0 {
        hex_string.insert(0, '0');
    }

    let mut result = hex::decode(hex_string.as_str())?;
    let len = result.len();
    if len < 32 {
        result.reverse();
        for _ in len..32 {
            result.push(0);
        }
        result.reverse();
    }

    assert!(result.len() >= 32);
    HashValue::from_slice(&result)
}
