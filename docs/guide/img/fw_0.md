```mermaid
graph LR
A(opened)
B(locked)
C(closed)
A-->|1.collaborative move|A
A-->|2.collaborative close|C
A-->|3.force move|B
B-->|4.resolve|A
B-->|5.challenge|C
B-->|6.timeout|C

```

