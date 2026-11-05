#!/usr/bin/env bash

# Shared helpers of the PSBT scripts. Run the scripts from the root of the
# repository.
#
# The helpers start a private regtest node of Bitcoin Core in a temporary
# directory. They were last run against Bitcoin Core 32.1.

for tool in bitcoind bitcoin-cli jq stack; do
    if ! command -v $tool &> /dev/null; then
        echo "Please install $tool"
        exit 1
    fi
done

# A failing step ends the script. The node is stopped on the way out.
set -e -o pipefail

export datadir=$(mktemp -d "${TMPDIR:-/tmp}/bitcoind-regtest-XXXXXX")

# The node is for these scripts only. It talks to no peer and keeps its
# caches small. Set PSBT_RPC_PORT when another regtest node holds the port.
cat > "$datadir/bitcoin.conf" <<EOF
[regtest]
rpcport=${PSBT_RPC_PORT:-18443}
fallbackfee=0.0001
txindex=1
listen=0
connect=0
dnsseed=0
dbcache=4
maxmempool=5
par=1
rpcthreads=2
EOF

btc () {
    bitcoin-cli -regtest -datadir=$datadir "$@"
}

start_bitcoind () {
    bitcoind -regtest -datadir=$datadir -daemon > /dev/null
    trap stop_bitcoind EXIT
    while ! btc getblockchaininfo &> /dev/null; do
        echo "Waiting for bitcoind"
        sleep 1
    done
}

stop_bitcoind () {
    trap - EXIT
    btc stop > /dev/null || true
    # The node removes its PID file as the last step of its shutdown
    while [ -e "$datadir/regtest/bitcoind.pid" ]; do
        sleep 1
    done
    rm -r $datadir
}

# A wallet with keys of its own
create_wallet () {
    btc -named createwallet wallet_name=$1 > /dev/null
}

# A wallet without private keys. It can watch a public descriptor, which a
# wallet with private keys refuses to import.
create_watch_wallet () {
    btc -named createwallet wallet_name=$1 disable_private_keys=true > /dev/null
}

get_address () {
    btc -rpcwallet="miner" getnewaddress
}

get_public_descriptor () {
    btc getdescriptorinfo $1 | jq -r .descriptor
}

get_descriptor_address () {
    btc deriveaddresses $1 | jq -r ".[0]"
}

# Import a descriptor that ends with its checksum. The script stops if the
# wallet refuses it.
import_descriptor () {
    request=$(jq --null-input --arg "desc" $2 '[ { desc: $desc, timestamp: "now" } ]')
    result=$(btc -rpcwallet=$1 importdescriptors "$request")
    if [ "$(jq -r '.[0].success' <<< $result)" != "true" ]; then
        echo "Wallet $1 refused a descriptor: $(jq -c '.[0].error' <<< $result)" >&2
        exit 1
    fi
}

generate_blocks () {
    btc generatetoaddress $1 $(btc -rpcwallet="miner" getnewaddress) &> /dev/null
}

# The helper program of these scripts, run against the built library
psbt_tool () {
    stack exec -- runghc ./scripts/PsbtSignTest.hs "$@"
}

# A new key for regtest. Prints the private key in the wallet import format,
# a space, and the compressed public key in hexadecimal.
#
# Bitcoin Core has no dumpprivkey call any more, so the keys are made here
# and Core gets them inside descriptors.
new_key () {
    psbt_tool key $(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
}
