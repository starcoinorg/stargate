use failure::prelude::*;
use node_client::NodeClient;
use grpcio::EnvBuilder;
use cli_wallet::cli_wallet::WalletLibrary;
use types::{
    account_address::AccountAddress,
};
use chain_client::{RpcChainClient, ChainClient};
use node_proto::{OpenChannelRequest, OpenChannelResponse, PayRequest, PayResponse, ConnectRequest, ConnectResponse, WithdrawRequest, WithdrawResponse, ChannelBalanceRequest, ChannelBalanceResponse, DepositRequest, DepositResponse};
use std::{
    sync::Arc,
};

pub struct ClientProxy {
    node_client: NodeClient,
    wallet: WalletLibrary,
    chain_client: RpcChainClient,
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
        let chain_client = RpcChainClient::new(chain_host, chain_port as u32);
        Ok(ClientProxy {
            node_client,
            wallet: WalletLibrary::new(faucet_account_file),
            chain_client,
        })
    }

    pub fn get_account(&mut self) -> Result<AccountAddress> {
        Ok(self.wallet.get_address())
    }

    pub fn faucet(&mut self, amount: u64) -> Result<()> {
        self.chain_client.faucet(self.wallet.get_address(), amount)
    }

    pub fn open_channel(&mut self,space_delim_strings: &[&str], is_blocking: bool) -> Result<OpenChannelResponse>{
        let response=self.node_client.open_channel(OpenChannelRequest{
            remote_addr:AccountAddress::from_hex_literal(space_delim_strings[1])?,
            local_amount:space_delim_strings[2].parse::<u64>()?,
            remote_amount:space_delim_strings[3].parse::<u64>()?,
        })?;
        Ok(response)
    }

    pub fn withdraw(&mut self,space_delim_strings: &[&str], is_blocking: bool) -> Result<WithdrawResponse>{
        let response=self.node_client.withdraw(WithdrawRequest{
            remote_addr:AccountAddress::from_hex_literal(space_delim_strings[1])?,
            local_amount:space_delim_strings[2].parse::<u64>()?,
            remote_amount:space_delim_strings[3].parse::<u64>()?,
        })?;
        Ok(response)
    }

    pub fn deposit(&mut self,space_delim_strings: &[&str], is_blocking: bool) -> Result<DepositResponse>{
        let response=self.node_client.deposit(DepositRequest{
            remote_addr:AccountAddress::from_hex_literal(space_delim_strings[1])?,
            local_amount:space_delim_strings[2].parse::<u64>()?,
            remote_amount:space_delim_strings[3].parse::<u64>()?,
        })?;
        Ok(response)
    }

    pub fn off_chain_pay(&mut self,space_delim_strings: &[&str], _is_blocking: bool) -> Result<PayResponse>{
        let response=self.node_client.pay(PayRequest{
            remote_addr:AccountAddress::from_hex_literal(space_delim_strings[1])?,
            amount:space_delim_strings[2].parse::<u64>()?,
        })?;
        Ok(response)
    }

    pub fn connect(&mut self,space_delim_strings: &[&str], is_blocking: bool) -> Result<ConnectResponse>{
        let response=self.node_client.connect(ConnectRequest{
            remote_addr:AccountAddress::from_hex_literal(space_delim_strings[1])?,
            remote_ip:space_delim_strings[2].to_string(),
        })?;
        Ok(response)
    }

    pub fn channel_balance(&mut self,space_delim_strings: &[&str], is_blocking: bool) -> Result<ChannelBalanceResponse>{
        let response=self.node_client.channel_balance(ChannelBalanceRequest{
            remote_addr:AccountAddress::from_hex_literal(space_delim_strings[1])?,
        })?;
        Ok(response)
    }

    pub fn account_state(&mut self,) -> Result<Option<Vec<u8>>>{
        Ok(self.chain_client.get_account_state_with_proof(&self.wallet.get_address(),None)?.1)
    }

}
