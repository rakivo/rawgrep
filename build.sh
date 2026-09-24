#!/bin/sh
set -e

fast=0
install=0
no_default_features=""
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
        --no-default-features)
            no_default_features="--no-default-features"
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

set -xe

if [ "$fast" = 1 ]; then
    RUSTFLAGS="-C debug-assertions=off -C target-cpu=native" \
    cargo +nightly b -Z build-std=core,alloc,std,panic_abort \
        --profile=release-fast \
        $no_default_features \
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

# if [ "$fast" = 1 ]; then
#     RUSTFLAGS="-C debug-assertions=off -C force-frame-pointers=yes -C target-cpu=native" \
#     cargo b -Z build-std=core,alloc,std,panic_abort \
#         --profile=release-fast-without-lto-with-debug \
#         $no_default_features \
#         --features "use_nightly${features:+,$features}"
# else
#     if [ -n "$features" ]; then
#         cargo b --features "$features"
#     else
#         cargo b
#     fi
# fi

# if [ "$install" = 1 ]; then
#     sudo cp ./target/release-fast-without-lto-with-debug/rawgrep /usr/bin/rawgrep
#     sudo setcap 'cap_dac_read_search,cap_ipc_lock=eip' /usr/bin/rawgrep
# fi
