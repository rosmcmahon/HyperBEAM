#!/bin/sh
# Cron workers live in the node's memory, so every start re-registers HB_CRONS once the node answers.
set -uf
"$@" &
node=$!
trap 'kill -TERM "$node"; wait "$node"; exit' TERM INT
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
wait "$node"
