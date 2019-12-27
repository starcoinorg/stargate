#!/bin/sh
set -e

DIR="$( cd "$( dirname "$0" )" && pwd )"

PROXY=""
if [ "$https_proxy" ]; then
    PROXY=" --build-arg https_proxy=$https_proxy --build-arg http_proxy=$http_proxy"
fi

docker build -f $DIR/validator.Dockerfile $DIR/../.. --tag starcoin_e2e --build-arg GIT_REV="$(git rev-parse HEAD)"  $PROXY "$@"