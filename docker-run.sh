#!/usr/bin/env bash
### A Script which you can use to run rust related cmds in this project.
### How to use:
### 1. use  `docker build -t stargate-base -f docker/build.Dockerfile ./docker` to build a linux environment image.
### 2. then, use the script to run cmd, like:
###    - `./docker-run.sh cargo build -p sgchain`
docker run --rm -m 6g \
 --volume "$(pwd)":/stargate \
 --volume $HOME/.cargo/registry:/usr/local/cargo/registry \
 --volume "$HOME"/.cargo/git:/usr/local/cargo/git \
 --workdir=/stargate \
 stargate-base:latest "$@"
