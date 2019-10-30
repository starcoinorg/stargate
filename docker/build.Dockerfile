FROM circleci/rust:stretch

RUN rustup toolchain add beta nightly
RUN rustup component add clippy rustfmt

RUN sudo sh -c 'echo "deb http://deb.debian.org/debian stretch-backports main" > /etc/apt/sources.list.d/backports.list'
RUN sudo apt-get update && \
 sudo apt-get install -y protobuf-compiler/stretch-backports cmake curl && \
 sudo apt-get clean && \
 sudo rm -r /var/lib/apt/lists/*
