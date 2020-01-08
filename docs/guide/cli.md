# Cli Command 

This guide describes how to use the command line interface (CLI) client to interact with the Blockchain and Stargate second layer node. The CLI is invoked as an interactive shell. It provides basic commands to create accounts, mint coins, perform transfers, and query the blockchain. You can use the CLI client to interact with a validator node on the testnet, on a local Blockchain, or on a remote blockchain by specifying the node's hostname.

## Invocation

Connect to the blockchain via the CLI Client

```
cargo run --bin cli -- --chain_host {chain_host} --chain_port {chain_port} --host {node_host} --port {node_port}
```

## Commands

Once started with any of the three commands previously mentioned, the following CLI commands are available:

```
major_command subcommand [options]
```

If you enter only the major command, it will show the help information for that command. Major commands can be any one of the following:


### Account Command

#### Account Create

Create a random account with private/public key pair. Account information will be held in memory only. The created account will not be saved to the chain.Usage:

```
account create
```

#### Account mint

Mint coins to the account.

```
account mint <receiver_account_ref_id>|<receiver_account_address> <number_of_coins>
```

#### Account state

Get state of given account.

```
account state <receiver_account_ref_id>|<receiver_account_address>
```

#### Account write

Write key information of private key to file.

```
account write <key_file_path>
```

#### Account recover

Recover accounts from  file.

```
account recover <key_file_path>
```

### Node Command

#### Open Channel

Open channel with remote participant ,if remote participant in p2p network.

```
node oc <remote_addr> <local_amount>
```

#### Deposit

Deposit to channel.

```
node d <remote_addr> <local_amount>
```

#### Pay on channel

Pay to participant have direct channel.

```
node p <remote_addr> <amount>
```

#### Withdral

Withdral money from channel.

```
node wd <remote_addr> <amount>
```

#### Channel Balance

Query user balance for one channel.

```
node cb <remote_addr>
```

#### Add Invoice

Add invoice for receiver want to receive money by hash time lock payment.
```
node ai <amount>
```

#### Send Payment

Send hash time lock payment to receiver.
```
node sp <encoded_invoice>
```

