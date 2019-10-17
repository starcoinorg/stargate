# Getting started

## Required
+ Rust >= "1.35.0"
+ Cargo >= "1.35.0"

## Compile project
```
cargo build
```

## Run libra node
```
./target/debug/sgchain 
```

## Run Cli and Create Account

Create two new accounts without password for testing. 

```
mkdir alice
mkdir bob
```
Then transfer some testing eth from coinbase to these new accounts
```
./target/debug/cli --chain_host localhost --chain_port 8000 --host localhost --port 9000 -m alice/key
```
Then the mint coin for alice.
```
a m 10000000
```

Start client for bob:
```
./target/debug/cli --chain_host localhost --chain_port 8000 --host localhost --port 9001 -m bob/key
```
Then the mint coin for bob.
```
a m 10000000
```
You could use such command to check account state:
```
a s
```

## Run node service
1. Prepare the node configure
    ```
    cp config_template/node1.toml alice/node.toml
    cp config_template/node2.toml bob/node.toml
    ```
	change last part of net_config.seeds in bob/node.toml to alice's address in hex.
    
2. Start node service
    ```
    ./target/debug/node -c alice -f alice/key
    ./target/debug/node -c bob -f bob/key
    ```

## Channel Operation

1. Open Channel
    In alice's cli
    ```
	node oc {bob address in hex} 10000 10000
    ```
2. Channel Balance

	For Alice
    ```
    node cb {bob}
    ```
	For Bob
    ```
    node cb {alice}
    ```
3. Channel pay

	For Alice
    ```
    node pay {bob} 100
    node cb {bob}
    ```
	For Bob
    ```
    node cb {alice}
    ```
4. Withdraw from channel 

	For Alice
    ```
    node wd {bob} 1000 1000
    node cb {bob}
    ```
	
	For Bob
    ```
    node cb {alice}

    ```
