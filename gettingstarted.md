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
## Channel Contract
1. Deploy Module to Chain
    In alice's cli
    ```
    dev dm demo/RockPaperScissors/module/rps.mvir

    ```

2. Install Script to Node
    Change all {{starlab}} in demo/RockPaperScissors/scripts to alice's address,then in both cli execute
    ```
    dev ip demo/RockPaperScissors/scripts

    ```

3. Play Game

   Before the game begin,you could check channel balance,remember the both balance.  
   In Alice:
   ```
   dev pe {bob} scripts rps_player_1 b"bde750abcf1d176a34cce61b607107092413100c9195b08f13d6e7d46980cf1c" 20
   ```
   Then ,for Bob
   ```
   dev pe {alice} scripts rps_player_2 b"70" 10
   ```
   Then ,end game ,in alice
   ```
   dev pe {bob} scripts rps_end_game b"72" b"616263"
   ```
   After the game end,you could check channel balance.Alice lose the game,so balance of her should be origin balance minus 10,balance of bob should be his origin balance plus 10.
