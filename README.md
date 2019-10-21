Stargate

---

[![CircleCI](https://circleci.com/gh/starcoinorg/stargate.svg?style=shield)](https://circleci.com/gh/starcoinorg/stargate)
[![License](https://img.shields.io/badge/license-Apache-green.svg)](LICENSE)

Stargate is the layer2 state channel protocol and implements of Starcoin. 

The goal of Stargate is to provide a second layer for Starcoin, that can execute smart contract on state channel, and the state of smart contract can be seamlessly transferred between chain and offchain channel.

Note that the Starcoin's chain code has not been released yet, we just use [Libra](https://github.com/libra/libra) to mock it.

## Features

1. Execute [Move](https://github.com/libra/libra/tree/master/language/vm) contract on state channel.
2. Seamlessly state transfer between chain and offchain.
3. Layer2 delegate node supports user security to delegate its own Layer2 message to a node without having to keep its own node always online.
4. Layer2 generic message deliver (For Layer2 DApp deliver message).
5. Offchain state can be compressed by proof(Merkle Proof or ZK Proof).

Note that features including already implemented and planned implementation.

## Architecture

TODO

## Note to Developers

* Stargate is a prototype implement.
* Project is under heavy development, not production ready. 

## Getting Started

[Getting Started](./gettingstarted.md)

## License

Stargate is licensed as [Apache 2.0](https://github.com/libra/libra/blob/master/LICENSE).
