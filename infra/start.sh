#!/bin/sh
# Cron workers live in the node's memory, so every start re-registers HB_CRONS once the node answers.
# LMDB never shrinks: past HB_MAX_CACHE_GB the node stops, its cache is cleared and copycat refills recent blocks.
set -uf
cache=${HB_CACHE_DIR:-/data/cache-mainnet}
max_kb=$(( ${HB_MAX_CACHE_GB:-0} * 1024 * 1024 ))
node=
trap '[ -n "$node" ] && kill -TERM "$node" && wait "$node"; exit' TERM INT
over() { [ "$max_kb" -gt 0 ] && [ "$(du -sk "$cache" | cut -f1)" -gt "$max_kb" ]; }
while :; do
    if over; then
        echo "cache over ${HB_MAX_CACHE_GB} GB, clearing ${cache}"
        find "$cache" -mindepth 1 -delete
    fi
    "$@" &
    node=$!
    until curl -fsS -o /dev/null "http://127.0.0.1:${HB_PORT}/~meta@1.0/info" 2>/dev/null; do
        kill -0 "$node" 2>/dev/null || { wait "$node"; exit; }
        sleep 2
    done
    for cron in ${HB_CRONS:-}; do
        if ! id=$(curl -fsS "http://127.0.0.1:${HB_PORT}${cron}"); then
            echo "cron registration failed: ${cron}" >&2
            kill -TERM "$node"
            wait "$node"
            exit 1
        fi
        echo "cron ${id}: ${cron}"
    done
    while kill -0 "$node" 2>/dev/null && ! over; do
        sleep "${HB_CACHE_CHECK_SECONDS:-300}" &
        wait $!
    done
    kill -0 "$node" 2>/dev/null || { wait "$node"; exit; }
    kill -TERM "$node"
    wait "$node"
done
