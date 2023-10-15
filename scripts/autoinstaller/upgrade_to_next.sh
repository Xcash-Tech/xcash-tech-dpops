#!/bin/bash

XCASH_DPOPS_BRANCH="master"

echo "###Updating requirements"
sudo apt update
sudo apt install libuv1-dev jq

echo "###Stopping services"

sudo systemctl stop xcash-dpops
sudo systemctl stop xcash-rpc-wallet
sudo systemctl stop xcash-daemon


echo "###Rebuilding xcash-core"
half_cores=$(( $(nproc) / 2 ))

cd ${HOME}/xcash-official/xcash-core
git pull
echo 'y' | make clean
make release -j "$half_cores"

echo "###Rebuilding xcash-dpops"
cd ${HOME}/xcash-official/xcash-dpops
git pull
git switch "${XCASH_DPOPS_BRANCH}"
echo 'y' |make clean
make release -j "$half_cores"


get_current_block_height() {
    local host="$1"
    height=$(curl -s -X POST "http://${host}:18281/json_rpc" -d '{
       "jsonrpc":"2.0",
       "id":"0",
       "method":"get_info"
    }' | jq -r '.result.height')
    echo "$height"
}

get_wallet_address() {
    local host="$1"
    address=$(curl -s -X POST "http://${host}:18285/json_rpc" -d '{
       "jsonrpc":"2.0",
       "id":"0",
       "method":"get_address"
    }' | jq -r '.result.address')
    echo "$address"

}

get_service_exec_line() {
    local service_file="$1"
    exec_start_value=$(grep -oP '^\s*ExecStart=\K.*' "$service_file")
    exec_start_value=$(echo "$exec_start_value" | sed -e 's/^[[:space:]]*//')
    echo "$exec_start_value"
}

echo "###Checking network current block height"

top_block_height=$(get_current_block_height "seed3.xcash.tech")
echo "###Current Network block height: ${top_block_height}"


echo "###Quick syncing blockchain"
xcash_daemon=$(get_service_exec_line "/lib/systemd/system/xcash-daemon.service")
xcash_daemon="${xcash_daemon} --xcash_trusted_sync_block ${top_block_height}"

$xcash_daemon


echo "###Waiting till blockchain reaches top block"

while true; do
    current_block_height=$(get_current_block_height "127.0.0.1")

    echo "Current local block height: ${current_block_height} of $top_block_height"
    if [[ "$current_block_height" =~ ^[0-9]+$ ]]; then
       if [ "$current_block_height" -ge "$top_block_height" ]; then
        break
       fi
    fi
    sleep 5
done
kill $(pgrep xcashd)

while pgrep -x xcashd > /dev/null; do
    echo "Shutting down xcash daemon..."
    sleep 1
done


echo "###Starting daemon and wallet services"
sudo systemctl start xcash-daemon
sudo systemctl start xcash-rpc-wallet


echo "###Waiting for daemon"
while true; do
    current_block_height=$(get_current_block_height "127.0.0.1")

    echo "Current local block height: ${current_block_height}"
    if [[ "$current_block_height" =~ ^[0-9]+$ ]]; then
        break
    fi
    sleep 1
done


echo "###Waiting for wallet"
while true; do
    wallet_address=$(get_wallet_address "127.0.0.1")

    echo "Wallet address: ${wallet_address}"
    if [[ "$wallet_address" != "" ]]; then
        break
    fi
    sleep 1
done


echo "###Syncing xcash dpops database"
xcash_dpops=$(get_service_exec_line "/lib/systemd/system/xcash-dpops.service")
xcash_dpops="${xcash_dpops} --init-db-from-seeds"
$xcash_dpops

echo "###Starting dpops service"

sudo systemctl start xcash-dpops

echo "###Done"

