#!/bin/env bash

set -e

set -x

go build -tags lambda.norpc -ldflags="-s -w" -o bootstrap ./lambda

(
  cd cdk || exit
  rm -rf cdk.out/asset.*
  cdk synth -q
)
