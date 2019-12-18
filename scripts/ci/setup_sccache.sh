#!/bin/bash

SCRIPT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$SCRIPT_PATH/../.."

set -e
OPTIONS="$1"

if [[ $OPTIONS == *"v"* ]]; then
	set -x
fi

CARGO_DIRNAME="$(dirname "$(which cargo)")"
# install sccache
SCCACHE_TMP_PATH=/tmp/sccache.tar.gz
SCCACHE_DOWNLOAD_URL="https://github.com/mozilla/sccache/releases/download/0.2.12/sccache-0.2.12-x86_64-unknown-linux-musl.tar.gz"
wget -c $SCCACHE_DOWNLOAD_URL -O $SCCACHE_TMP_PATH \
&& tar -C $CARGO_DIRNAME -xzvf $SCCACHE_TMP_PATH --strip-components 1 --wildcards "**/sccache"

# prepare cache
mkdir -p $HOME/.cache/sccache
docker create --name dummy docker.pkg.github.com/starcoinorg/stargate/build_cache:master && \
docker cp dummy:/sccache $HOME/.cache/sccache && \
docker rm -f dummy

sccache --start-server
