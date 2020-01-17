```mermaid
graph LR

S0(open_channel)
S4(...)
S5(seq=10,act=play&#40 4,5 &#41)
S6(seq=11,act=play&#40 5,5 &#41)
S7(seq=12,act=play&#40 5,6 &#41)
S8(...)
S9(confiscate_resource)
S10(close_channel)
style S5 fill:#f91
style S6 fill:#f9f
style S7 fill:#f91
subgraph chain
S0
S6
S9
S6-->|challenge timeout|S9-->S10
end
subgraph channel
S0-->S4-->S5-->|force move|S6-.->|resolve|S7-.->S8-.->S10
end

```

