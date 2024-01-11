#!/usr/bin/env bash

[[ "$_" != "$0" ]] && echo "This script is supposed to be sourced to change the PATH in your current shell" && exit

export PATH=$HOME/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/bin:$PATH
