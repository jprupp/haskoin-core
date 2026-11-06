#!/usr/bin/env bash

# Makes the data of data/complex_psbt.json again: a transaction that spends
# coins of every kind, signed by Bitcoin Core one wallet at a time.
#
# Usage: ./scripts/create_complex_psbt_data.sh [OUTPUT_FILE]
#
# Run it from the root of the repository. The keys are new at every run, so
# the PSBTs differ from the ones in the repository. Last run against Bitcoin
# Core 32.1.

. ./scripts/lib.sh

output_file=${1:-/tmp/psbt_vectors.json}

stack build
start_bitcoind

# Each wallet leaves its signatures as partial signatures. Without
# finalize=false, Core would finalize the inputs it can complete alone.
sign_psbt () {
    btc -rpcwallet=$1 -named walletprocesspsbt "psbt=$2" sign=true finalize=false | jq -r .psbt
}

get_priv_key () {
    keys=$(new_key)
    cut -d' ' -f1 <<< "$keys"
}

get_canonical_descriptor () {
    checksum=$(btc getdescriptorinfo "$1" | jq -r .checksum)
    echo -n "$1#$checksum"
}

create_wallet "miner"
create_wallet "p2pkh"
create_wallet "p2sh-pk"
create_wallet "p2sh-ms-1"
create_wallet "p2sh-ms-2"
create_wallet "p2sh-ms-3"
create_wallet "p2sh-p2wpkh"
create_wallet "p2sh-wsh-pk"
create_wallet "p2sh-wsh-ms-1"
create_wallet "p2sh-wsh-ms-2"
create_wallet "p2sh-wsh-ms-3"
create_wallet "p2wpkh"
create_wallet "p2wsh-pk"
create_wallet "p2wsh-ms-1"
create_wallet "p2wsh-ms-2"
create_wallet "p2wsh-ms-3"

# Get an output to spend

miner_address=$(btc -rpcwallet="miner" getnewaddress)
generate_blocks 101

echo "Setting up p2pkh wallet"

setup_p2pkh () {
    privkey=$(get_priv_key)
    private_descriptor=$(get_canonical_descriptor "pkh($privkey)")
    public_descriptor=$(get_public_descriptor $private_descriptor)
    import_descriptor "p2pkh" "$private_descriptor"
    get_descriptor_address $public_descriptor
}

p2pkh_address=$(setup_p2pkh)

echo "Setting up p2sh-pk wallet"

setup_p2sh_p2pk () {
    privkey=$(get_priv_key)
    private_descriptor=$(get_canonical_descriptor "sh(pk($privkey))")
    public_descriptor=$(get_public_descriptor $private_descriptor)
    import_descriptor "p2sh-pk" "$private_descriptor"
    get_descriptor_address $public_descriptor
}

p2sh_pk_address=$(setup_p2sh_p2pk)

echo "Setting up p2sh-ms wallets"

setup_p2sh_ms () {

    keys=$(new_key)
    read -r privkey1 pubkey1 <<< "$keys"

    keys=$(new_key)
    read -r privkey2 pubkey2 <<< "$keys"

    keys=$(new_key)
    read -r privkey3 pubkey3 <<< "$keys"

    private_descriptor_1=$(get_canonical_descriptor "sh(sortedmulti(2,$privkey1,$pubkey2,$pubkey3))")
    import_descriptor "p2sh-ms-1" "$private_descriptor_1"

    private_descriptor_2=$(get_canonical_descriptor "sh(sortedmulti(2,$pubkey1,$privkey2,$pubkey3))")
    import_descriptor "p2sh-ms-2" "$private_descriptor_2"

    private_descriptor_3=$(get_canonical_descriptor "sh(sortedmulti(2,$pubkey1,$pubkey2,$privkey3))")
    import_descriptor "p2sh-ms-3" "$private_descriptor_3"

    public_descriptor=$(get_public_descriptor $private_descriptor_1)
    get_descriptor_address $public_descriptor
}

p2sh_ms_address=$(setup_p2sh_ms)

echo "Setting up p2sh-wsh-pk wallet"

setup_p2sh_wsh_pk () {
    privkey=$(get_priv_key)
    private_descriptor=$(get_canonical_descriptor "sh(wsh(pk($privkey)))")
    public_descriptor=$(get_public_descriptor $private_descriptor)
    import_descriptor "p2sh-wsh-pk" "$private_descriptor"
    get_descriptor_address $public_descriptor
}

p2sh_wsh_pk_address=$(setup_p2sh_wsh_pk)

echo "Setting up p2sh-wsh-ms wallets"

setup_p2sh_wsh_ms () {

    keys=$(new_key)
    read -r privkey1 pubkey1 <<< "$keys"

    keys=$(new_key)
    read -r privkey2 pubkey2 <<< "$keys"

    keys=$(new_key)
    read -r privkey3 pubkey3 <<< "$keys"

    private_descriptor_1=$(get_canonical_descriptor "sh(wsh(sortedmulti(2,$privkey1,$pubkey2,$pubkey3)))")
    import_descriptor "p2sh-wsh-ms-1" "$private_descriptor_1"

    private_descriptor_2=$(get_canonical_descriptor "sh(wsh(sortedmulti(2,$pubkey1,$privkey2,$pubkey3)))")
    import_descriptor "p2sh-wsh-ms-2" "$private_descriptor_2"

    private_descriptor_3=$(get_canonical_descriptor "sh(wsh(sortedmulti(2,$pubkey1,$pubkey2,$privkey3)))")
    import_descriptor "p2sh-wsh-ms-3" "$private_descriptor_3"

    public_descriptor=$(get_public_descriptor $private_descriptor_1)
    get_descriptor_address $public_descriptor
}

p2sh_wsh_ms_address=$(setup_p2sh_wsh_ms)

echo "Setting up p2wpkh wallet"

setup_p2wpkh () {
    privkey=$(get_priv_key)
    private_descriptor=$(get_canonical_descriptor "wpkh($privkey)")
    public_descriptor=$(get_public_descriptor $private_descriptor)
    import_descriptor "p2wpkh" "$private_descriptor"
    get_descriptor_address $public_descriptor
}

p2wpkh_address=$(setup_p2wpkh)

echo "Setting up p2wsh-pk wallet"

setup_p2wsh_pk () {
    privkey=$(get_priv_key)
    private_descriptor=$(get_canonical_descriptor "wsh(pk($privkey))")
    public_descriptor=$(get_public_descriptor $private_descriptor)
    import_descriptor "p2wsh-pk" "$private_descriptor"
    get_descriptor_address $public_descriptor
}

p2wsh_pk_address=$(setup_p2wsh_pk)

echo "Setting up p2wsh-ms wallets"

setup_p2wsh_ms () {

    keys=$(new_key)
    read -r privkey1 pubkey1 <<< "$keys"

    keys=$(new_key)
    read -r privkey2 pubkey2 <<< "$keys"

    keys=$(new_key)
    read -r privkey3 pubkey3 <<< "$keys"

    private_descriptor_1=$(get_canonical_descriptor "wsh(sortedmulti(2,$privkey1,$pubkey2,$pubkey3))")
    import_descriptor "p2wsh-ms-1" "$private_descriptor_1"

    private_descriptor_2=$(get_canonical_descriptor "wsh(sortedmulti(2,$pubkey1,$privkey2,$pubkey3))")
    import_descriptor "p2wsh-ms-2" "$private_descriptor_2"

    private_descriptor_3=$(get_canonical_descriptor "wsh(sortedmulti(2,$pubkey1,$pubkey2,$privkey3))")
    import_descriptor "p2wsh-ms-3" "$private_descriptor_3"

    public_descriptor=$(get_public_descriptor $private_descriptor_1)
    get_descriptor_address $public_descriptor
}

p2wsh_ms_address=$(setup_p2wsh_ms)

addresses=(

    $p2pkh_address
    $p2sh_pk_address
    $p2sh_ms_address
    $p2sh_wsh_pk_address
    $p2sh_wsh_ms_address
    $p2wpkh_address
    $p2wsh_pk_address
    $p2wsh_ms_address

)

fund_addresses () {
    jq_entries="[]"

    for addr in "${addresses[@]}"; do
        jq_entries=$(echo $jq_entries | jq --arg addr $addr '. += [ { key: $addr, value: 0.5 } ]')
    done

    amounts=$(jq '. | from_entries' <<< $jq_entries)

    btc -rpcwallet="miner" -named sendmany "amounts=$amounts"

}

funding_txid=$(fund_addresses)

funding_tx_outputs=$(
    btc -named getrawtransaction "txid=$funding_txid" verbose=true | jq -r '.vout | length - 1'
)

create_psbt () {
    psbt_inputs="[]"

    for i in $(seq 0 $funding_tx_outputs); do
        psbt_inputs=$(
            echo $psbt_inputs |
            jq \
                --arg txid $funding_txid \
                --arg vout $i \
                '. += [ { txid: $txid, vout: $vout | tonumber } ]'
        )
    done

    psbt_outputs=$(jq --null-input --arg addr $miner_address '[ { ($addr): 3.99 } ]')
    btc -named createpsbt "inputs=$psbt_inputs" "outputs=$psbt_outputs"
}

psbt=$(create_psbt)

miner_psbt=$(sign_psbt "miner" "$psbt")
p2pkh_psbt=$(sign_psbt "p2pkh" "$psbt")
p2sh_pk_psbt=$(sign_psbt "p2sh-pk" "$psbt")
p2sh_ms_1_psbt=$(sign_psbt "p2sh-ms-1" "$psbt")
p2sh_ms_2_psbt=$(sign_psbt "p2sh-ms-2" "$psbt")
p2sh_wsh_pk_psbt=$(sign_psbt "p2sh-wsh-pk" "$psbt")
p2sh_wsh_ms_1_psbt=$(sign_psbt "p2sh-wsh-ms-1" "$psbt")
p2sh_wsh_ms_2_psbt=$(sign_psbt "p2sh-wsh-ms-2" "$psbt")
p2wpkh_psbt=$(sign_psbt "p2wpkh" "$psbt")
p2wsh_pk_psbt=$(sign_psbt "p2wsh-pk" "$psbt")
p2wsh_ms_1_psbt=$(sign_psbt "p2wsh-ms-1" "$psbt")
p2wsh_ms_2_psbt=$(sign_psbt "p2wsh-ms-2" "$psbt")

signed_psbts=(

    $miner_psbt
    $p2pkh_psbt
    $p2sh_pk_psbt
    $p2sh_ms_1_psbt
    $p2sh_ms_2_psbt
    $p2sh_wsh_pk_psbt
    $p2sh_wsh_ms_1_psbt
    $p2sh_wsh_ms_2_psbt
    $p2wpkh_psbt
    $p2wsh_pk_psbt
    $p2wsh_ms_1_psbt
    $p2wsh_ms_2_psbt

)

psbt_list="[]"

for signed_psbt in "${signed_psbts[@]}"; do
    psbt_list=$(
        echo $psbt_list |
        jq --arg signed_psbt $signed_psbt '. += [ $signed_psbt ]'
    )
done

combined_psbt=$(btc combinepsbt "$psbt_list")
complete_psbt=$(btc -named finalizepsbt "psbt=$combined_psbt" extract=false | jq -r .psbt)
final_tx=$(btc -named finalizepsbt "psbt=$combined_psbt" extract=true | jq -r .hex)

summary_entries="[]"

add_summary_field () {
    summary_entries=$(
        echo $summary_entries |
            jq --arg key $1 --arg value $2 '. += [ { key: $key, value: $value } ]'
    )
}

add_summary_field "initial_psbt" $psbt
add_summary_field "miner_psbt" $miner_psbt
add_summary_field "p2pkh_psbt" $p2pkh_psbt
add_summary_field "p2sh_pk_psbt" $p2sh_pk_psbt
add_summary_field "p2sh_ms_1_psbt" $p2sh_ms_1_psbt
add_summary_field "p2sh_ms_2_psbt" $p2sh_ms_2_psbt
add_summary_field "p2sh_wsh_pk_psbt" $p2sh_wsh_pk_psbt
add_summary_field "p2sh_wsh_ms_1_psbt" $p2sh_wsh_ms_1_psbt
add_summary_field "p2sh_wsh_ms_2_psbt" $p2sh_wsh_ms_2_psbt
add_summary_field "p2wpkh_psbt" $p2wpkh_psbt
add_summary_field "p2wsh_pk_psbt" $p2wsh_pk_psbt
add_summary_field "p2wsh_ms_1_psbt" $p2wsh_ms_1_psbt
add_summary_field "p2wsh_ms_2_psbt" $p2wsh_ms_2_psbt
add_summary_field "combined_psbt" $combined_psbt
add_summary_field "complete_psbt" $complete_psbt
add_summary_field "final_tx" $final_tx

echo $summary_entries | jq '. | from_entries' > "$output_file"
echo "Done. The PSBTs are in $output_file"

stop_bitcoind
