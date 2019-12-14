FROM starcoin/base:latest AS builder

# To use http/https proxy while building, use:
# docker build --build-arg https_proxy=http://fwdproxy:8080 --build-arg http_proxy=http://fwdproxy:8080
ENV RUST_BACKTRACE "1"

WORKDIR /starcoin
COPY . /starcoin
RUN cargo build  -p sgchain && cd target/debug && rm -r build deps incremental

RUN mkdir -p /opt/starcoin/bin /opt/starcoin/etc
COPY libra/docker/install-tools.sh /root
COPY /starcoin/target/debug/sgchain /opt/starcoin/bin

# Admission control
EXPOSE 8000
# Validator network
EXPOSE 6180
# Metrics
EXPOSE 9101

# Define SEED_PEERS, NODE_CONFIG, NETWORK_KEYPAIRS, CONSENSUS_KEYPAIR, GENESIS_BLOB and PEER_ID environment variables when running
COPY docker/validator/docker-run.sh /
CMD /docker-run.sh

ARG BUILD_DATE
ARG GIT_REV
ARG GIT_UPSTREAM

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.vcs-ref=$GIT_REV
LABEL vcs-upstream=$GIT_UPSTREAM
