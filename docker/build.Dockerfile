FROM rust:latest

RUN apt-get update && \
 apt install -y sudo
RUN sudo apt-get install -y protobuf-compiler cmake && \
 sudo apt-get install --no-install-recommends -y nano net-tools tcpdump iproute2 netcat ngrep atop gdb strace clang && \
 sudo apt-get clean && \
 sudo rm -r /var/lib/apt/lists/*

WORKDIR /starcoin
COPY rust-toolchain /starcoin/rust-toolchain
RUN rustup install $(cat rust-toolchain)
