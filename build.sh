#!/bin/sh
set -e

fast=0
install=0
features=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        fast)
            fast=1
            ;;
        install)
            install=1
            ;;
        --features)
            shift
            features="$1"
            ;;
        --features=*)
            features="${1#--features=}"
            ;;
        *)
            ;;
    esac
    shift
done

if [ "$install" = 1 ]; then
    sudo -v
fi

if [ "$fast" = 1 ]; then
    RUSTFLAGS="-C debug-assertions=off -C target-cpu=native" \
    cargo b -Z build-std=core,alloc,std,panic_abort \
        --profile=release-fast \
        --features "use_nightly${features:+,$features}"
else
    if [ -n "$features" ]; then
        cargo b --features "$features"
    else
        cargo b
    fi
fi

if [ "$install" = 1 ]; then
    sudo cp ./target/release-fast/rawgrep /usr/bin/rawgrep
    sudo setcap 'cap_dac_read_search,cap_ipc_lock=eip' /usr/bin/rawgrep
fi
