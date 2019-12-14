#! /usr/bin/env bash

# Installation:
#  brew tap drewsonne/tap
#  brew install tf-install-provider
#
# Usage:
#  Make sure your provider is in your $PATH sommewhere already
#  Run `tf-install-provider <provider-stub>`
#
#  <provider-stub> is the part of the name which is after `terraform-provider`, eg,
#
#   terraform-provider-random --> `tf-install-provider random`
#   terraform-provider-aws    --> `tf-install-provider aws`
#   terraform-provider-gocd   --> `tf-install-provider gocd`
#
# If you have install your provider through homebrew, it will create the version name correctly.
#

SUFFIX="$1"

PROVIDER_NAME="terraform-provider-"${SUFFIX}
PROVIDER_REL_PATH=$(which ${PROVIDER_NAME})
PROVIDER_DIR=$(cd "$(dirname ${PROVIDER_REL_PATH})"; pwd);
PROVIDER_PATH=${PROVIDER_REL_PATH}
PROVIDER_VERSION=$(python -c "import os; print(os.path.realpath(\"${PROVIDER_PATH}\"))" | awk -F/ '{print $(NF-2)}')

PLUGIN_DIR=${HOME}"/.terraform.d/plugins/darwin_amd64"

mkdir -p ${PLUGIN_DIR}

install -o `id -u` -g `id -g` -m 755 ${PROVIDER_PATH} "${PLUGIN_DIR}/${PROVIDER_NAME}_v${PROVIDER_VERSION}_x4"