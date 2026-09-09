#!/bin/sh
set -e

fast=0
install=0

for arg in "$@"; do
    case "$arg" in
        fast) fast=1 ;;
        install) install=1 ;;
        *) ;;
    esac
done

if [ "$install" = 1 ]; then
    sudo -v
fi

if [ "$fast" = 1 ]; then
    RUSTFLAGS="-C debug-assertions=off -C target-cpu=native" \
    cargo b -Z build-std=core,alloc,std,panic_abort \
        --profile=release-fast --features=use_nightly
else
    cargo b
fi

if [ "$install" = 1 ]; then
    sudo cp ./target/release-fast/rawgrep /usr/bin/rawgrep
    sudo setcap 'cap_dac_read_search,cap_ipc_lock=eip' /usr/bin/rawgrep
fi
