#include "round.h"


bool process_round(size_t round_number) {
    size_t count, count2;

    struct timeval current_time;
    size_t minute_within_block;



    #define RESET_VARIABLES \
    for (count = 0; count < BLOCK_VERIFIERS_AMOUNT; count++) \
    { \
        memset(VRF_data.block_verifiers_vrf_secret_key_data[count],0,strlen(VRF_data.block_verifiers_vrf_secret_key_data[count])); \
        memset(VRF_data.block_verifiers_vrf_secret_key[count],0,strlen((const char*)VRF_data.block_verifiers_vrf_secret_key[count])); \
        memset(VRF_data.block_verifiers_vrf_public_key_data[count],0,strlen(VRF_data.block_verifiers_vrf_public_key_data[count])); \
        memset(VRF_data.block_verifiers_vrf_public_key[count],0,strlen((const char*)VRF_data.block_verifiers_vrf_public_key[count])); \
        memset(VRF_data.block_verifiers_random_data[count],0,strlen(VRF_data.block_verifiers_random_data[count])); \
        memset(VRF_data.block_blob_signature[count],0,strlen(VRF_data.block_blob_signature[count])); \
    } \
    memset(VRF_data.vrf_secret_key_data,0,strlen(VRF_data.vrf_secret_key_data)); \
    memset(VRF_data.vrf_secret_key,0,strlen((const char*)VRF_data.vrf_secret_key)); \
    memset(VRF_data.vrf_public_key_data,0,strlen(VRF_data.vrf_public_key_data)); \
    memset(VRF_data.vrf_public_key,0,strlen((const char*)VRF_data.vrf_public_key)); \
    memset(VRF_data.vrf_alpha_string_data,0,strlen(VRF_data.vrf_alpha_string_data)); \
    memset(VRF_data.vrf_alpha_string,0,strlen((const char*)VRF_data.vrf_alpha_string)); \
    memset(VRF_data.vrf_proof_data,0,strlen(VRF_data.vrf_proof_data)); \
    memset(VRF_data.vrf_proof,0,strlen((const char*)VRF_data.vrf_proof)); \
    memset(VRF_data.vrf_beta_string_data,0,strlen(VRF_data.vrf_beta_string_data)); \
    memset(VRF_data.vrf_beta_string,0,strlen((const char*)VRF_data.vrf_beta_string)); \
    memset(VRF_data.reserve_bytes_data_hash,0,strlen(VRF_data.reserve_bytes_data_hash)); \
    memset(VRF_data.block_blob,0,strlen(VRF_data.block_blob));


    // wtf is this?

    // this is a X-CASH proof of stake block so this is not the start blocks of the network
    // if (strncmp(VRF_data.block_blob,"",1) != 0)
    // {
      // update all of the databases 
    //   color_print("Updating the previous rounds data in the databases","blue");
        // this just adds statistics to delegates and statistics
        // FIXME this should be done other way
    //   update_databases();
    // }

    RESET_VARIABLES;
    
    // reset the current_round_part and current_round_part_backup_node after the databases have been updated for the previous rounds statistics
    current_round_part[0] = '1';
    current_round_part_backup_node[0] = '0';



    // TODO drop all the old shit
    
    //! 1. sync the databases and build majority list
    //! 2. fill current, previous and next structures
    //! 3. calculate block producer using predictable algorithm to be sure it's the same on all nodes
    //! 4. if we're seed node, just wait till end of the block generation
    //! 5. if we're not in the block producers, wait until end of block generation
    //! 6. we're block producer. create the block


    // get actual network data
    get_current_block_height(current_block_height);
    get_previous_block_hash(previous_block_hash);


    // FIXME maybe better do a simpler sync?
    size_t network_majority_count = 0;
    xcash_node_sync_info_t* nodes_majority_list = NULL;

    if (!initial_db_sync_check(&network_majority_count, &nodes_majority_list)){
        WARNING_PRINT("Can't sync databases with network majority")
        free(nodes_majority_list);
        return false;
    }

    // update with fresh delegates list
    if (!fill_delegates_from_db()) {
        ERROR_PRINT("Can't read delegates list from DB");
        free(nodes_majority_list);
        return false;
    }
    // TODO update delegate's online statuses

    // TODO make a calculation of block producers from online nodes
    free(nodes_majority_list);



    // wait for all block verifiers to sync
    // FIXME we don't actually depend on time now because sync is changed
    // sync_block_verifiers_minutes_and_seconds(1,40);

    // update the previous, current and next block verifiers after syncing the database

    //! the problem when info about the delegate not found in the database delegates. so, we have public key but no other info
    // ! it's about current, and previous delegates
    if (update_block_verifiers_list() == 0)
    {
      ERROR_PRINT("Could not update the previous, current and next block verifiers list from database");
    }


    // block_verifiers_list_t* block_verifiers[] = {
    //     &current_block_verifiers_list,
    //     &previous_block_verifiers_list,
    //     &next_block_verifiers_list
    // };

    // for (size_t i = 0; i < 3; i++)
    // {
    //     block_verifiers_list_t* bf = block_verifiers[i];
    //     INFO_PRINT("...");
    //     for (size_t j = 0; j < BLOCK_VERIFIERS_AMOUNT; j++)
    //     {
    //         INFO_PRINT("%-30s%s", bf->block_verifiers_name[j], bf->block_verifiers_public_key[j]);
    //     }
    // }
    
    

    // wait for all block verifiers to sync, as this will ensure when we calculate the main node roles we have the same buffer
    // FIXME return in production
    //! !!!!!!!!!!!!!!!!!!!!!!1
    // sync_block_verifiers_minutes_and_seconds(1,45);

    if (calculate_main_nodes_roles() == 0)
    {
      ERROR_PRINT("Error calculating the next block producer. Your block verifier will wait until the next round");
      return false;
    }

    // check if the syncing time is over the start time of the round
    gettimeofday(&current_time, NULL);
    minute_within_block = (current_time.tv_sec / 60) % BLOCK_TIME;

    if (minute_within_block % BLOCK_TIME >= 2)
    {
      WARNING_PRINT("Your block verifier took longer to sync and the next round has already started, so your block verifier will sit out for the remainder of the round");
      // FIXME return in production
      sync_block_verifiers_minutes_and_seconds((BLOCK_TIME-1),SUBMIT_NETWORK_BLOCK_TIME_SECONDS);
      return false;
    }

    // check if your delegate is a current block verifier, and sit out the round if not since you have already synced the database
    bool is_current_block_verifier = false;
    for (count2 = 0; count2 < BLOCK_VERIFIERS_AMOUNT; count2++)
    {
      if (strncmp(current_block_verifiers_list.block_verifiers_public_address[count2],xcash_wallet_public_address,XCASH_WALLET_LENGTH) == 0)
      {
        is_current_block_verifier = true;
        break;
      }
    }

    if (!is_current_block_verifier)
    {
      WARNING_PRINT("Your delegate is not a current block verifier, waiting until the next round");
      print_block_producer();

      sync_block_verifiers_minutes_and_seconds((BLOCK_TIME-1),SUBMIT_NETWORK_BLOCK_TIME_SECONDS);
      return false;
    }
    
    if (block_verifiers_create_block() == 0)
    {
        return false;
        //   ERROR_PRINT("Your block verifier will wait until the next round");
    }

  #undef RESET_VARIABLES

}


void start_block_production(void) {
    struct timeval current_time, round_start_time, round_time, block_start_time, block_time;

    while (true)
    {
        gettimeofday(&current_time, NULL);
        size_t minute_within_block = (current_time.tv_sec / 60) % BLOCK_TIME;
        // if (minute_within_block != 0) {
        //     sleep(5);
        // } else 
        {
            size_t round_number = 0;
            bool round_created = false;
            // maximum 4 rounds
            gettimeofday(&block_start_time, NULL);
            while (round_number < 4) {
                gettimeofday(&round_start_time, NULL);

                if (process_round(round_number)) {
                    round_created = true;
                    break;
                }
                gettimeofday(&current_time, NULL);
                timersub(&current_time, &round_start_time, &round_time);
                timersub(&current_time, &block_start_time, &block_time);

                INFO_PRINT("The round %ld took %ld seconds", round_number, (size_t)round_time.tv_sec);

                // try new round
                round_number++;
                
                // assume we still have time within 4 minutes to make a try
                if (block_time.tv_sec < 4*60) {
                    INFO_PRINT_STATUS_FAIL("Block %s not created. Trying next round %ld", current_block_height, round_number);
                }else {
                    INFO_PRINT_STATUS_FAIL("Block %s not created. We're out time for another try", current_block_height);
                    break;
                }
            }

            if (round_created) {
                INFO_PRINT_STATUS_OK("Block %s created successfully", current_block_height);
            }else{
                INFO_PRINT_STATUS_FAIL("Block %s not created within %ld rounds", current_block_height, round_number);
            }
        }
    }
}
