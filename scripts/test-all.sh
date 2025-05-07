#!/usr/bin/env bash
set -e

# export noir functions purely in brillig
nargo export --force-brillig

# run rust all tests against brillig functions
cargo test

# export noir functions as-is
nargo export

# run rust all tests against noir functions
cargo test
