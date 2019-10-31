# Gobang(五子棋)

Gobang is a smart contract demo written with libra move ir (.mvir). The frontend reuses http://jasnature.github.io/gobang_html5/.

Below is the steps to run the game on starcoin. Suppose you've successfully opened the channel according to the [gettingstarted document](../../gettingstarted.md).
And make sure the balance is sufficient (>10000000) to execute the script. 

1. Deploy Module to Chain

    In alice's cli
    ```
    dev dm demo/Gobang/mvir/module/gobang.mvir

    ```

2. Install Script to Node

    Change all {{starlab}} in demo/Gobang/mvir/scripts to alice's address,
    
    then in alice cli execute
    ```
    dev ip demo/Gobang/mvir/scripts

    ```
    in bob cli execute
    ```
    dev ip demo/Gobang/mvir/scripts.csp

    ```
3. Play the game

    Alice open demo/Gobang/index.html in her browser. Input alice's node service address into "节点服务" field，and input bob's address into "对手玩家".

    Bob open demo/Gobang/index.html in his browser. Input bob's node service address into "节点服务" field，and input alice's address into "对手玩家".
    Then both of them can click "发出请求" to start the game.

