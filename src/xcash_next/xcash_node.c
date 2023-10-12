#include "xcash_node.h"

#include "define_macro_functions.h"
#include "network_daemon_functions.h"
#include "network_wallet_functions.h"
#include "variables.h"
/*
-----------------------------------------------------------------------------------------------------------
Name: get_delegates_data
Description: Gets the delegates data
-----------------------------------------------------------------------------------------------------------
*/

bool get_daemon_data(void) {
    // get the current block height
    if (get_current_block_height(current_block_height) == 0) {
        ERROR_PRINT("Could not get the current block height");
        return false;
    }

    if (atol(current_block_height) < XCASH_PROOF_OF_STAKE_BLOCK_HEIGHT) {
        ERROR_PRINT(
            "Current Block Height is below DPOPS era. Perhaps the blockchain data is not fully synchronized yet");
        return false;
    }

    // FIXME: maybe it's really better to go offline if there is no previous block hash , it causes error later
    // get the previous block hash
    if (get_previous_block_hash(previous_block_hash) == 0) {
        ERROR_PRINT("Could not get the previous block hash");
        return false;
    }


    return true;
}


bool get_node_data(void) {
    // get the wallets public address
    if (get_public_address() == 0) {
        ERROR_PRINT("Could not get the wallets public address");
        return false;
    }

    is_seed_node = is_seed_address(xcash_wallet_public_address);
    network_data_node_settings = is_seed_node? 1:0;

    return true;
}


bool is_seed_address(const char* public_address) {

    for (size_t i = 0; i < NETWORK_DATA_NODES_AMOUNT; i++)
    {
        if (strcmp(network_data_nodes_list.network_data_nodes_public_address[i], public_address)== 0) {
            return true;
        }
    }
    return false;
}

const char* address_to_node_name(const char* public_address) {
    const char* seed_names[] = {
        NETWORK_DATA_NODE_1_IP_ADDRESS_PRODUCTION,
        NETWORK_DATA_NODE_2_IP_ADDRESS_PRODUCTION,
        NETWORK_DATA_NODE_3_IP_ADDRESS_PRODUCTION,
        NETWORK_DATA_NODE_4_IP_ADDRESS_PRODUCTION,
        NETWORK_DATA_NODE_5_IP_ADDRESS_PRODUCTION,
    };

    // TODO delegates_all should contains the seeds too. so we actually don't need these checks

    for (size_t i = 0; i < NETWORK_DATA_NODES_AMOUNT; i++)
    {
        if (strcmp(network_data_nodes_list.network_data_nodes_public_address[i], public_address)== 0) {
            return seed_names[i];
        }
    }


    for (size_t i = 0; i < BLOCK_VERIFIERS_TOTAL_AMOUNT; i++)
    {
        if (strcmp(delegates_all[i].public_address, public_address)== 0) {
            return  delegates_all[i].delegate_name;
        }
    }
    return NULL;
}

const char* address_to_node_host(const char* public_address) {
    const char* seed_names[] = {
        NETWORK_DATA_NODE_1_IP_ADDRESS_PRODUCTION,
        NETWORK_DATA_NODE_2_IP_ADDRESS_PRODUCTION,
        NETWORK_DATA_NODE_3_IP_ADDRESS_PRODUCTION,
        NETWORK_DATA_NODE_4_IP_ADDRESS_PRODUCTION,
        NETWORK_DATA_NODE_5_IP_ADDRESS_PRODUCTION,
    };

    for (size_t i = 0; i < NETWORK_DATA_NODES_AMOUNT; i++)
    {
        if (strcmp(network_data_nodes_list.network_data_nodes_public_address[i], public_address)== 0) {
            return seed_names[i];
        }
    }

    // TODO delegates_all should contains the seeds too. so we actually don't need the checks above

    for (size_t i = 0; i < BLOCK_VERIFIERS_TOTAL_AMOUNT; i++)
    {
        if (strcmp(delegates_all[i].public_address, public_address)== 0) {
            return delegates_all[i].IP_address;
        }
    }
    return NULL;
}


xcash_seed_idx_t seed_address_to_node_index(const char* public_address) {

    for (size_t i = 0; i < NETWORK_DATA_NODES_AMOUNT; i++)
    {
        if (strcmp(network_data_nodes_list.network_data_nodes_public_address[i], public_address)== 0) {
            return (xcash_seed_idx_t)i;
        }
    }

    return XCASH_SEED_NODE_1;
}

