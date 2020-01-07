#!/bin/sh
set -e

CONFIG_DIR="${1?[Specify config directory]}"
NODE_ID="${2?[Specify node id]}"
PUBLIC_IP="${3?[pubclic ip address]}"
INIT_CONFIG="$(cd ./sgconfig/data/configs && pwd)"

cd ./sgterraform/sgchain/$CONFIG_DIR
cp -f $INIT_CONFIG/genesis.blob .
cp -f $INIT_CONFIG/mint.key .
cp -f $INIT_CONFIG/seed_peers.config.toml ./val

#replace first public_ip, you can once replace by -e parmeter on linux.
sed -i "" "s/{PUBLIC_IP}/$PUBLIC_IP/g" ./val/node.config.toml

# config env
  export NODE_CONFIG=$(sed "s,{PEER_ID},$NODE_ID", ./val/node.config.toml)
  export SEED_PEERS=$(cat ./val/seed_peers.config.toml)
  export NETWORK_KEYPAIRS=$(cat ./val/*.network.keys.toml)
  export NETWORK_PEERS=$(cat ./val/network_peers.config.toml)
  export CONSENSUS_KEYPAIR=$(cat ./val/*.consensus.keys.toml)
  export CONSENSUS_PEERS=$(cat ./consensus_peers.config.toml)

 docker run  -w `pwd` --env NODE_CONFIG --env SEED_PEERS --env NETWORK_KEYPAIRS --env NETWORK_PEERS --env CONSENSUS_KEYPAIR --env CONSENSUS_PEERS  --expose 65206  --net=host --detach  docker.pkg.github.com/starcoinorg/stargate/sgchain:latest