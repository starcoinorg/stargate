# Router 

Router is part of Stargate the second layer network.It's responsible for find the best path for given payment sender and receiver. If there are many possible paths for a payment ,it will find the path with lowest cost and lowest payload.

We have build two types of router. The first one is based on global routing table ,so we named it as table router . The second one is based on ant routing algorithm, so we named it as ant router. Also we have a mix mode to use them at the same time.

# Table Router

Table Router is based on global routing table. In order to build the global routing table , router need to parse and listen all funding transactions which is responsible for open channel. Besides that router also need to pay close attention to such events as deposit/withdraw/close channel. After got such connection information ,router will put them into routing table which is based on some graph algorithm. When a payment is coming , router will find the best path .

# Ant Router

Ant Router don't need the global routing table, so it doesn't need to parse and listen chain changes from genesis block . Ant Router only need to know neighbour. The basic algorithm like :

1. Alice and Bob agree on a large random number. For example, Alice and Bob choose a random 128 bit numbers, R(A) and R(B) and exchange them in a secured way.
2. Alice concatenates the bit 0, and the hash2 R = h(R(A)⌢R(B)) to get a pheromone seed S(A) = 0⌢R and communicates S(A) to its immediate neigh- bors in the Stargate with whom she has an open payment channel.
3. Bob concatenates the bit 1, R(A) and R(B) to get a pheromone seed S(B) = 1⌢R and communicates it to its neighbors in Stargate network with whom he has an open payment channel.
4. Alice waits from an answer from its neighbors indicating her that a path has been found by the network.
5. Bob waits to have news from Alice that a path has been found.

If S is a pheromone seed, we denote S′ the “derived seed” without the appended first bit, that is, the hash R. (thus S = 0⌢S′ or S = 1⌢S′). If S = 0⌢S′ (resp.
⌢′ ̄ ̄⌢′ ̄⌢′ S=1 S)we denote by S the “conjugate” seed S=1 S (resp.S=0 S).

The nodes perform the following tasks (on top of a possible payment task if they are Alice or Bob).

1. Each nodes reserves a fast access memory space for the routing tasks.
2. Each node keeps in memory a numbered list of neighbors (it means the opened channels).Also about historical performance of payments through these neighbors.
3. When a node receives a pheromone seed S, it checks if S′ is not a derived seed of a seed already stored in the mempool.
4. If S′ is not found, then it stores S in the mempool together with the information about the neighbor that has communicated S (the “transmitter neighbor”). Then it broadcasts S to the other neighbors.
5. If S′ is found, then it checks if S is stored. If S is stored it adds the information about the new transmitter neighbor. If S is not stored it means that S is stored, so a matching occurs.
6. When a matching occurs, the node concatenates the bit 0 to S and constructs a “matched seed” Sm = 0⌢S (resp. Sm = 0⌢S and sends it to the neighbors from which it received S (resp. S). Note that “matched seeds” are one bit longer than pheromone seed. The node keeps track of the neighbors having transmitted the unmatched seed.
7. When a node receives a matched seed Sm it broadcasts it back to the neighbors that send to him the unmatched seeds and keeps track of them.

* Back Pressure and Balance problem

We add some information to measure the payment back pressure. In one of the communication message , we add balances of two participants and the total payment amount in the same payment direction at the same time. We could measure the payment pressure of each channel for router to optimize payment path .

