FROM starcoin/base:latest AS toolchain
WORKDIR /starcoin
COPY rust-toolchain /starcoin/rust-toolchain
# reinstall toolchain in case of toolchain changed
RUN rustup install $(cat rust-toolchain)

FROM toolchain as builder
# To use http/https proxy while building, use:
# docker build --build-arg https_proxy=http://fwdproxy:8080 --build-arg http_proxy=http://fwdproxy:8080
ENV RUST_BACKTRACE "1"

RUN apt-get update; apt-get install -y clang
WORKDIR /starcoin
COPY . /starcoin
RUN cargo build -p node && cd target/debug && rm -r build deps incremental

### Production Image ###

FROM debian:buster As prod

RUN mkdir -p /opt/starcoin/bin /opt/starcoin/etc
COPY --from=builder /starcoin/target/debug/node /opt/starcoin/bin
#RUN cd /opt/starcoin/etc &&  echo "$NODE_CONFIG" > node.toml && echo "$KEYS_CONFIG" > key

ENTRYPOINT ["/opt/starcoin/bin/node"]
CMD ["-c", "/opt/starcoin/etc", "-f", "/opt/starcoin/etc/key", "-n", "0"]

# node port
EXPOSE 9000

ENV BUILD_DATE "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
ARG GIT_REV

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.vcs-ref=$GIT_REV
# LABEL vcs-upstream=$GIT_UPSTREAM
