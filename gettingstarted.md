# Getting started

## Compile project
```
cd stargage
./libra/scripts/dev_setup.sh
source ~/.cargo/env
cargo build
```

## Run libra node
```
./target/debug/sgchain 
```
## Run starcoin test net [Option]
if you want start chain node to connect startcoin test net , [click here](./sgterraform/quickstart.md).

## Run Cli and Create Account

Create two new accounts without password for testing. 

```
mkdir alice
mkdir bob
```
Then transfer some testing coin from coinbase to these new accounts
```
./target/debug/cli --chain_host localhost --chain_port 8000 --host localhost --port 9000 -m alice/key
```
connect to starcoin test-net
```
./target/debug/cli --chain_host 39.98.196.244 --chain_port 8001 --host starcoin.io
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
account mint 10000000
```
You could use such command to check account state:
```
account state
```

## Run node service
1. Prepare the node configure
    ```
    cp config_template/alice.toml alice/node.toml
    cp config_template/bob.toml bob/node.toml
    ```
	change last part of net_config.seeds in bob/node.toml to alice's address in hex.
    
2. Start node service
    ```
    ./target/debug/node -c alice -f alice/key -n 0
    ./target/debug/node -c bob -f bob/key -n 0
    ```

## Channel Operation

1. Open Channel
    In alice's cli
    ```
	node open channel {bob address in hex} 10000 10000
    ```
2. Channel Balance

	For Alice
    ```
    node channel balance {bob}
    ```
	For Bob
    ```
    node channel balance {alice}
    ```
3. Channel pay

	For Alice
    ```
    node pay {bob} 100
    node channel balance {bob}
    ```
	For Bob
    ```
    node channel balance {alice}
    ```
4. Withdraw from channel 

	For Alice
    ```
    node withdraw {bob} 1000 1000
    node channel balance {bob}
    ```
	
	For Bob
    ```
    node channel balance {alice}

    ```
## Channel Contract
A game Rock-Paper-Scissors is used to demonstrate the channel contract.

1. Deploy Module to Chain
    In alice's cli
    ```
    dev deploy module demo/RockPaperScissors/module/rps.mvir

    ```

2. Install Script to Node
    Change all {{starlab}} in demo/RockPaperScissors/scripts to alice's address,then in alice's cli execute
    ```
    dev install package demo/RockPaperScissors/scripts

    ```
    In Bob's cli execute
    ```
    dev install package demo/RockPaperScissors/scripts.csp

    ```

3. Play Game

   Before the game begin,you could check channel balance,remember the both balance.  
   In Alice:
   ```
   dev package execute {bob} scripts rps_player_1 b"bde750abcf1d176a34cce61b607107092413100c9195b08f13d6e7d46980cf1c" 20
   ```
   Then ,for Bob
   ```
   dev package execute {alice} scripts rps_player_2 b"70" 10
   ```
   Then ,end game ,in alice
   ```
   dev package execute {bob} scripts rps_end_game b"72" b"616263"
   ```
   After the game end,you could check channel balance.Alice lose the game,so balance of her should be origin balance minus 10,balance of bob should be his origin balance plus 10. A detailed description of the contract can be found [here](./demo/RockPaperScissors/README.md).

## trouble shooting
[click enter](./troubleshooting.md)
