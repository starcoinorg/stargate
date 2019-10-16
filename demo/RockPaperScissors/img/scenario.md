
```sequence
Note right of Alice: game start
Alice->Bob: open_channel

Note right of Alice: Round#1
Note left of Alice: Alice plays with sceret hand
Alice->Bob: s_play(secure_hand,amount)
Note right of Bob: Bob plays with normal hand
Bob->Alice: play(hand,amount)
Note left of Alice: Alice ends the game
Alice->Bob: end_game(hand,key)
Note right of Bob: This is a normal end!

Note right of Alice: Round#2
Note left of Alice: Alice plays with sceret hand
Alice->Bob: s_play(hand,key,nonce,amount)
Note right of Bob: Bob plays with normal hand
Bob->Alice: play(hand,amount)
Note left of Alice: Alice finds herself losing and does nothing
Note right of Bob: timeout! Bob ends the game as winner
Bob->Alice: game_timeout()

Note right of Alice: Round#3
Note left of Alice: Alice plays with sceret hand
Alice->Bob: s_play(secure_hand,amount)
Note right of Bob: Bob doesn't attend the game
Note left of Alice: Alice cancels the game.
Alice->Bob: cancel()

Note right of Alice: game over
Alice->Bob: close_channel

```

