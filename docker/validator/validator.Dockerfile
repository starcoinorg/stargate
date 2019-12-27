FROM starcoin/base:latest AS toolchain
WORKDIR /starcoin
COPY rust-toolchain /starcoin/rust-toolchain
# reinstall toolchain in case of toolchain changed
RUN rustup install $(cat rust-toolchain)

FROM toolchain as builder
# To use http/https proxy while building, use:
# docker build --build-arg https_proxy=http://fwdproxy:8080 --build-arg http_proxy=http://fwdproxy:8080
ENV RUST_BACKTRACE "1"

WORKDIR /starcoin
COPY . /starcoin
RUN cargo build  -p sgchain && cd target/debug && rm -r deps incremental

### Production Image ###

FROM debian:buster As prod

RUN mkdir -p /opt/starcoin/bin /opt/starcoin/etc
COPY libra/docker/install-tools.sh /root
COPY --from=builder /starcoin/target/debug/sgchain /opt/starcoin/bin
RUN LD_LIBRARY_PATH="/usr/local/lib"
RUN export LD_LIBRARY_PATH

# Admission control
EXPOSE 8000
# Validator network
EXPOSE 6180
# Metrics
EXPOSE 9101

# Define SEED_PEERS, NODE_CONFIG, NETWORK_KEYPAIRS, CONSENSUS_KEYPAIR, GENESIS_BLOB and PEER_ID environment variables when running
COPY docker/validator/docker-run.sh /
CMD /docker-run.sh

ENV BUILD_DATE "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
ARG GIT_REV

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.vcs-ref=$GIT_REV
# LABEL vcs-upstream=$GIT_UPSTREAM
