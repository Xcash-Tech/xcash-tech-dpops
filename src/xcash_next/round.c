#include "round.h"

producer_ref_t producer_refs[] = {
    {main_nodes_list.block_producer_public_address, main_nodes_list.block_producer_IP_address},
    {main_nodes_list.block_producer_backup_block_verifier_1_public_address, main_nodes_list.block_producer_backup_block_verifier_1_IP_address},
    {main_nodes_list.block_producer_backup_block_verifier_2_public_address, main_nodes_list.block_producer_backup_block_verifier_2_IP_address},
    {main_nodes_list.block_producer_backup_block_verifier_3_public_address, main_nodes_list.block_producer_backup_block_verifier_3_IP_address},
    {main_nodes_list.block_producer_backup_block_verifier_4_public_address, main_nodes_list.block_producer_backup_block_verifier_4_IP_address},
    {main_nodes_list.block_producer_backup_block_verifier_5_public_address, main_nodes_list.block_producer_backup_block_verifier_5_IP_address},
};

unsigned char* get_pseudo_random_hash(size_t seed, size_t feed_size) {
    // assume we have enough space for previous_hash and current iteration salt
    char salt_data[512];
    SHA512_CTX sha512;

    // we need 2 bytes for each step
    size_t iterations = (feed_size*2 / SHA512_DIGEST_LENGTH) +1;

    unsigned char* hash_buf = calloc(iterations, SHA512_DIGEST_LENGTH);

    for (size_t i = 0; i < iterations; i++)
    {
        snprintf(salt_data, sizeof(salt_data), "%020ld%020ld", seed, i);
        SHA512_Init(&sha512);
        SHA512_Update(&sha512, salt_data, (size_t)strlen((const char*)salt_data));
        SHA512_Update(&sha512, hash_buf, (size_t)strlen((const char*)hash_buf));
        SHA512_Final(hash_buf + i*SHA512_DIGEST_LENGTH, &sha512);
    }


    // size_t bin_size = iterations*SHA512_DIGEST_LENGTH;
    // char* hash_str =  malloc(bin_size*2+1);
    // bin_to_hex(hash_buf, bin_size, hash_str);
    // INFO_PRINT("%s",hash_str);
    // free(hash_str);

    return hash_buf;
}

// TODO add shift selection depending on time. because if some node stuck, all networks will stuck on block
bool select_block_producers(size_t round_number) {
    (void)round_number;
    producer_node_t producers_list[BLOCK_VERIFIERS_AMOUNT];
    memset(producers_list, 0, sizeof(producers_list));

    // count delegates
    size_t num_producers = 0;
    for (size_t i = 0, j = 0; i < BLOCK_VERIFIERS_AMOUNT; i++)
    {
        if (strlen(delegates_all[i].public_address)==0) {
            break;
        }

        // skip seed nodes from block production
        // now seed  node can produce blocks
        // if (is_seed_address(delegates_all[i].public_address))
        //     continue;

        // skip offline nodes from block production
        if (strcmp(delegates_all[i].online_status, "false")==0)
            continue;


        strcpy(producers_list[j].public_address, delegates_all[i].public_address);
        strcpy(producers_list[j].IP_address, delegates_all[i].IP_address);

        if (strcmp(delegates_all[i].online_status, "true")==0) {
            producers_list[j].is_online = true;
        }

        j++;
        num_producers++;
    }

    if (num_producers == 0) {
        WARNING_PRINT("No valid producers generated during procuder selection.");
        return false;
    }

    size_t block_height, seed_block;
    sscanf(current_block_height,"%zu", &block_height);

    // we will has the same table of hashes within one day distribution
    seed_block = block_height / BLOCKS_PER_DAY_FIVE_MINUTE_BLOCK_TIME;

    unsigned char* pseudo_random_hash = get_pseudo_random_hash(seed_block, BLOCKS_PER_DAY_FIVE_MINUTE_BLOCK_TIME);

    producer_node_t*  producers_shuffle_list[BLOCKS_PER_DAY_FIVE_MINUTE_BLOCK_TIME];

    // initialize producer list to make it day-long
    // so, we have approximately even count of all producers for day distribution
    for (size_t i = 0; i < BLOCKS_PER_DAY_FIVE_MINUTE_BLOCK_TIME; i++)
    {
        // cycling within active producers_list
        size_t producer_index = i % num_producers;
        producers_shuffle_list[i] = &producers_list[producer_index];
    }



    for (size_t i = BLOCKS_PER_DAY_FIVE_MINUTE_BLOCK_TIME - 1; i > 0; i--) {
        // Generate a random index j using pseudo_random_hash
        unsigned int j = (pseudo_random_hash[i * 2] << 8 | pseudo_random_hash[i * 2 + 1]) % (i + 1);

        // Swap elements at indices i and j
        producer_node_t* temp = producers_shuffle_list[i];
        producers_shuffle_list[i] = producers_shuffle_list[j];
        producers_shuffle_list[j] = temp;
    }


    free(pseudo_random_hash);


    // // now shuffle the list with pseudorandom ordering
    // qsort(producers_shuffle_list, BLOCKS_PER_DAY_FIVE_MINUTE_BLOCK_TIME, sizeof(shuffle_node_t), shuffle_compare);
    

    // for (size_t i = 0; i < num_producers; i++)
    // {
    //     size_t counter = 0;
    //     for (size_t j = 0; j < BLOCKS_PER_DAY_FIVE_MINUTE_BLOCK_TIME; j++)
    //     {
    //         if (strcmp(producers_list[i].public_address, producers_shuffle_list[j].producer_node->public_address) == 0) {
    //             counter++;
    //         }
    //     }
    //     INFO_PRINT("%ld\t%s",counter, producers_list[i].public_address);
    // }






    // fill the main nodes list

    memset(&main_nodes_list, 0, sizeof(main_nodes_list));

    size_t producing_position = block_height % BLOCKS_PER_DAY_FIVE_MINUTE_BLOCK_TIME;

    // size_t producing_position = 0;
    // size_t shift_position = ((time(NULL) /BLOCK_TIME_SEC)) % BLOCKS_PER_DAY_FIVE_MINUTE_BLOCK_TIME;


    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    size_t shift_position = (current_time.tv_sec / (BLOCK_TIME * 60)) % 60; //5minutes block within an hour



    // positioning to the first online node and skipping the round numbers
    // when the amount of online nodes is small we have too many repeats. so better switch frame
    // producing_position += round_number*num_producers;
    // producing_position += round_number;

    // FIXME possible repeating selection of the same producer during the next block if previous producers was offline
    // add checking for previous block producer

    DEBUG_PRINT("Positions: %ld (%ld, %ld)", producing_position + shift_position, producing_position, shift_position);

    producing_position += shift_position;


    // for (size_t j = producing_position; j < producing_position+30; j++)
    // {
    //     size_t pp = j % BLOCKS_PER_DAY_FIVE_MINUTE_BLOCK_TIME;
    //     DEBUG_PRINT("%s", producers_shuffle_list[pp]->public_address);
    // }



    for (size_t i = 0; i < sizeof(producer_refs)/sizeof(producer_ref_t); i++)
    {

        // // filter repetitive producers
        // bool repeated_node_found;
        // size_t num_tries = 0;
        // do
        // {
        //     // for very small list of producers we need to get out of the loop
        //     if (num_tries > num_producers)
        //         break;

        //     repeated_node_found = false;
        //     producing_position = producing_position % BLOCKS_PER_DAY_FIVE_MINUTE_BLOCK_TIME;
        //     for (size_t j = 0; j < i; j++)
        //     {
        //         if (strcmp(producer_refs[j].public_address, producers_shuffle_list[producing_position]->public_address) == 0) {
        //             repeated_node_found = true;
        //             producing_position++;
        //             num_tries++;
        //             break;
        //         }
        //     }
        // } while (repeated_node_found);
        
        
        producing_position = producing_position % BLOCKS_PER_DAY_FIVE_MINUTE_BLOCK_TIME;

        strcpy(producer_refs[i].public_address, producers_shuffle_list[producing_position]->public_address);
        strcpy(producer_refs[i].IP_address, producers_shuffle_list[producing_position]->IP_address);

        producing_position++;
    }

    return true;
}




void show_block_producer(size_t round_number) {
    // INFO_STAGE_PRINT("Block producers for block %s round %ld: ", current_block_height, round_number);
    INFO_STAGE_PRINT("Block producers for block: [%s]", current_block_height);
    INFO_PRINT("Main Block Producer: "GREEN_TEXT("%s"), address_to_node_name(producer_refs[round_number].public_address));
    // for (size_t i = round_number + 1; i < 6; i++)
    // {
    //     INFO_PRINT("Backup Block Producer %ld: "GREEN_TEXT("%s"), i, address_to_node_name(producer_refs[i].public_address));
    // }
};


xcash_round_result_t process_round(size_t round_number) {
    // struct timeval current_time;
    // size_t minute_within_block;

    // reset the current_round_part and current_round_part_backup_node after the databases have been updated for the
    // previous rounds statistics

    // * STEP 1: sync the databases and build majority list
    // get actual network data
    if (get_current_block_height(current_block_height) != XCASH_OK) {
        ERROR_PRINT("Can't get current block height");
        return ROUND_ERROR;
    }

    if (get_previous_block_hash(previous_block_hash) != XCASH_OK) {
        ERROR_PRINT("Can't get previous block hash");
        return ROUND_ERROR;
    }

    // FIXME maybe better do a simpler sync?
    size_t network_majority_count = 0;
    xcash_node_sync_info_t* nodes_majority_list = NULL;

    if (!initial_db_sync_check(&network_majority_count, &nodes_majority_list) || !nodes_majority_list) {
        WARNING_PRINT("Can't sync databases with network majority")
        free(nodes_majority_list);
        return ROUND_ERROR;
    }

    // update with fresh delegates list
    if (!fill_delegates_from_db()) {
        ERROR_PRINT("Can't read delegates list from DB");
        free(nodes_majority_list);
        return ROUND_ERROR;
    }

    // update online status from data majority list
    INFO_STAGE_PRINT("Nodes online in the block %s round %ld", current_block_height, round_number);

    for (size_t i = 0; i < BLOCK_VERIFIERS_TOTAL_AMOUNT; i++)
    {
        if (strlen(delegates_all[i].public_address) == 0) {
            break;
        }

        // FIXME switch to binary format everywhere
        strcpy(delegates_all[i].online_status, "false");
        for (size_t j = 0; j < network_majority_count; j++)
        {
            if (strcmp(delegates_all[i].public_address, nodes_majority_list[j].public_address) == 0) {
                strcpy(delegates_all[i].online_status, "true");
                INFO_PRINT_STATUS_OK("Node: "BLUE_TEXT("%-30s"), delegates_all[i].delegate_name);
                break;
            }
        }
    }

    // finished with majority. clean up
    free(nodes_majority_list);


    if (network_majority_count< BLOCK_VERIFIERS_VALID_AMOUNT) {
        INFO_PRINT_STATUS_FAIL("Nodes majority: [%ld/%d]", network_majority_count, BLOCK_VERIFIERS_VALID_AMOUNT);
        WARNING_PRINT("Nodes majority is NOT enough for block production. Waiting for network recovery...");
        return ROUND_RETRY;
    }

    INFO_PRINT_STATUS_OK("Nodes majority: [%ld/%d]", network_majority_count, BLOCK_VERIFIERS_VALID_AMOUNT);

    // * STEP2: fill current, previous and next structures

    // update the previous, current and next block verifiers after syncing the database
    // TODO Remove this shit. Better change algo completely

    //! the problem is when info about the delegate not found in the database delegates. 
    //! so, we have public key but no other info
    //! it's about current, and previous delegates

    if (update_block_verifiers_list() == 0) {
        ERROR_PRINT("Could not update the previous, current and next block verifiers list from database");
        return ROUND_ERROR;
    }

    // FIXME OK, let's leave the old part, But replace current block verifiers by proven online
    block_verifiers_list_t* bf = &current_block_verifiers_list;

    // make sure we cleaned all records
    memset(bf, 0, sizeof(block_verifiers_list_t));

    for (size_t i = 0, j = 0; i < BLOCK_VERIFIERS_AMOUNT; i++)
    {
        // I have to do it, because of strong binding of all other code to the position in current block verifiers list
        // if (strcmp(delegates_all[i].online_status, "true") == 0) 
        {
            strcpy(bf->block_verifiers_name[j], delegates_all[i].delegate_name);
            strcpy(bf->block_verifiers_public_address[j], delegates_all[i].public_address);
            strcpy(bf->block_verifiers_public_key[j], delegates_all[i].public_key);
            strcpy(bf->block_verifiers_IP_address[j], delegates_all[i].IP_address);
            j++;
        }
    }

    // * STEP 3: calculate block producer using predictable algorithm to be sure it's the same on all nodes

    select_block_producers(round_number);

    is_block_creation_stage = true;

    // show_block_producer(round_number);

    INFO_STAGE_PRINT("Starting the %s block production", current_block_height);


    int block_creation_result = block_verifiers_create_block(round_number);

    is_block_creation_stage = false;


    return (xcash_round_result_t)block_creation_result;

}

void start_block_production(void) {
    struct timeval current_time, round_start_time, block_start_time;
    //  round_time,block_time;
    xcash_round_result_t round_result = ROUND_OK;
    size_t retries = 0;
    bool current_block_healthy = false;
    while (true) {
        gettimeofday(&current_time, NULL);
        size_t seconds_within_block = current_time.tv_sec % (BLOCK_TIME * 60);
        size_t minute_within_block = (current_time.tv_sec / 60) % BLOCK_TIME;

        current_block_healthy = get_current_block_height(current_block_height) == XCASH_OK;
        if (!current_block_healthy) {
            WARNING_PRINT("Can't get current block height. Possible node is still syncing blocks. Waiting for recovery...");
        }

        // dont's start block production if blockchain is not synced or block
        // time already passed starting point. seconds  >25 is too late to start
        // a production. better wait next block
        if (seconds_within_block > 25 || !current_block_healthy) {

            retries = 0;
            // refresh DB in case of last round error
            if (round_result != ROUND_OK && current_block_healthy && seconds_within_block > 280) {
                init_db_from_top();
                round_result = ROUND_OK;

            }else{
                INFO_STAGE_PRINT("Waiting for a [%s] block production. Starting in ... [%ld:%02ld]", current_block_height, BLOCK_TIME-1-minute_within_block, 59-(current_time.tv_sec % 60));
                sleep(5);                
            }
        } else
        {

            size_t round_number = 0;
            bool round_created = false;
            gettimeofday(&block_start_time, NULL);
            // retries give the node opportunity to resync data is other nodes was not fully synced at the moment
            // switched to the only one round for now
            while (retries < 2 && round_number < 1) {
                gettimeofday(&round_start_time, NULL);

                round_result = process_round(round_number);

                // FIXME this is shitty, make it nice in the future
                if (round_result == ROUND_RETRY) {
                    retries ++;
                    sleep(5);
                    continue;
                }


                // just wait for next round
                if (round_result == ROUND_ERROR) {
                    round_created = false;
                }

                // just wait for next round
                if (round_result == ROUND_SKIP) {
                    round_created = false;
                }

                if (round_result == ROUND_OK) {
                    round_created = true;
                }



                if (round_created) {
                    INFO_PRINT_STATUS_OK("Block %s created successfully", current_block_height);
                } else {
                    INFO_PRINT_STATUS_FAIL("Block %s not created within %ld rounds", current_block_height, round_number);
                }

                break;

                // gettimeofday(&current_time, NULL);
                // timersub(&current_time, &round_start_time, &round_time);
                // timersub(&current_time, &block_start_time, &block_time);

                // INFO_PRINT("The round %ld took %ld seconds", round_number, (size_t)round_time.tv_sec);

                // // try new round
                // round_number++;

                // // assume we still have time within 4 minutes to make a try
                // if (block_time.tv_sec < 4 * 60) {
                //     INFO_PRINT_STATUS_FAIL("Block %s not created. Trying next round %ld", current_block_height,
                //                            round_number);
                // } else {
                //     INFO_PRINT_STATUS_FAIL("Block %s not created. We're out time for another try",
                //                            current_block_height);
                //     break;
                // }
            }

        }
    }
}
