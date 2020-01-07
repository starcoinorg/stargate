# Stargate Wallet

Wallet crate implements the main logic of layer2 state channel which supports general state transition based on Libra MoveVM.
And the state transition is driven by move smart contracts which is abstracted into `channel transaction`.

## Lifecycle of channel transaction

1. CREATED: participant of channel propose a transaction to execute on the channel.
2. NEGOTIATING: the other participant receives the transaction, It may or may not agree the proposal.
   if the proposal is agreed by both, then channel will start to applying the transaction.
   there are two different situations.
3. APPLYING: If the channel txn only modifies the state of state channel,
   then participants can apply the state directly into channel's [local storage][1].
4. TRAVELING(optional): if the channel txn has updated layer1 state, then one participant of the channel must
   build a layer1 txn based on channel txn, and submit it to layer1, which we call the process travelling.
   After layer1 includes the txn, participants of the channel must to sync the channel state into their local storage.

### force travel

If the proposed channel txn doesn't modify other participant's private resources, and didn't get the approval of the participant,
then the proposer can force travel the channel txn, make it happen on layer1, lock the channel, (which we call it solo txn)
 and wait for the other participant to resolve the lock, or the lock is timeout-ed.

If the other participant acknowledges the solo txn, and agree the state outputted by the txn, 
he whill submit a [libra_account.resolve_channel][2] transaction to layer1 chain to resolve the lock, make the channel normal again.

If the other participant didn't resolve the lock timely, proposer can submit a txn to close the channel, and claim the other participant is the violator.
layer1 chain will confiscate balance in the channel and give it to proposer.

### channel challenge

When participant acknowledges a solo txn, he may found the txn is a stale txn, which means the proposer submitted the solo txn purposely.
In this case, participant must submit a challenge_channel txn to layer1 chain with his latest witness data.
Layer1 chain will do his work and judge who has crime.
See the [contract implementation][2] for more details.



## Implementation details

We use actor model to implement the wallet/channel.

Wallet is started as a babysitter role, who take care of
- init existing channels' states, and spawn it into a channel actor.
- respond to external requests, such as open new channel, query current opened channels, beyond that, it routes most request directly to channel actor.

channel actor is the core component who handles
- execute and propose channel txn.
- verify proposer's channel txn.
- agree and generate signatures on the chanel txn.
- apply the channel into channel's storage.
- submit layer1 txn like travel txn, solo txn.

Channel drives the [channel state machine][3] (which is stateless) by several operations to fulfill these requests.
Channel passes the current pending state and the operation to STM, STM then returns a modified pending state to channel.
It's channel's responsibility to keep the pending state.


This crate also contains some helper components:

- tx_applier: used to apply channel txn into local storage.
- scripts: contains the user-defined move contracts.
- data_stream: a Stream impl to fetch onchain data repeatedly.
- chain_watcher: watch chain txn and broadcast it to whoever has interest in.


[1]: ../../sgstorage
[2]: ../../libra/language/stdlib/modules/libra_account.mvir
[3]: ../../sgwallet/src/channel/channel_stm.rs