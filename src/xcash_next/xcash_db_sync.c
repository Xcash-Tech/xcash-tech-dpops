
#include "xcash_db_sync.h"

#include "block_verifiers_functions.h"
#include "block_verifiers_synchronize_check_functions.h"
#include "block_verifiers_synchronize_functions.h"
#include "db_operations.h"
#include "define_macro_functions.h"
#include "network_functions.h"
#include "network_security_functions.h"
#include "string_functions.h"
#include "variables.h"
#include "xcash_db_helpers.h"
#include "xcash_net.h"
#include "xcash_node.h"
#include "xcash_delegates.h"

#include "uv_net.h"
#include "cached_hashes.h"


bool get_node_sync_info(xcash_node_sync_info_t* sync_info) {
    bool result = false;

    size_t reserve_bytes_db_index;
    size_t block_height;

    char db_collection_name[DB_COLLECTION_NAME_SIZE];
    char prev_block_height_str[DB_COLLECTION_NAME_SIZE];

    memset(sync_info, 0, sizeof(xcash_node_sync_info_t));


    if (get_db_max_block_height(database_name, &block_height, &reserve_bytes_db_index) < 0) {
        ERROR_PRINT("can't get DB block height");
        return false;
    }

    sync_info->block_height = block_height;

    // fill the identifier of node
    strcpy(sync_info->public_address, xcash_wallet_public_address);

    // check latest blocks in database
    // get_reserve_bytes_database(reserve_bytes_db_index,1);

    sprintf(db_collection_name, "reserve_bytes_%zu", reserve_bytes_db_index);
    sprintf(prev_block_height_str, "%zu", block_height-1);


    bson_error_t error;
    int64_t count = 0;
    bson_t *filter = BCON_NEW("block_height", BCON_UTF8(prev_block_height_str));


    sync_info->db_reserve_bytes_synced = true;

    if (!db_count_doc_by(database_name, db_collection_name, filter, &count, &error) || count <=0) {
      DEBUG_PRINT("Reserve bytes for previous block %zu not found. DB not fully synced", block_height);
      sync_info->db_reserve_bytes_synced = false;
    }

    bson_destroy(filter);

    // fill hashes for each DB
    bool all_set_valid = true;
    for (size_t i = 0; i < DATABASE_TOTAL; i++) {
        if (!get_db_data_hash(collection_names[i], sync_info->db_hashes[i])) {
            ERROR_PRINT("Can't get hash for DB %s", collection_names[i]);
            all_set_valid = false;
            break;
        }
    }

    result = all_set_valid;

    if (!result) {
        // clean up from unfinished data
        memset(sync_info, 0, sizeof(xcash_node_sync_info_t));
    }
    return result;

}



bool download_db_from_node(const char *host, xcash_dbs_t db_type, int db_file_index, char *result_db_data_buf,
                           size_t result_db_data_buf_size) {
    char database_collection_name[DB_COLLECTION_NAME_SIZE];
    bool result = false;
    bool send_result = false;
    response_t **reply = NULL;

    switch (db_type) {
        case XCASH_DB_DELEGATES:
        case XCASH_DB_STATISTICS:
            send_result = send_direct_message(host, xcash_db_download_messages[db_type], &reply);
            break;
        case XCASH_DB_RESERVE_PROOFS:
        case XCASH_DB_RESERVE_BYTES:
            snprintf(database_collection_name, DB_COLLECTION_NAME_SIZE, "%s_%d", collection_names[db_type],
                     db_file_index);
            send_result = send_direct_message_param(host, xcash_db_download_messages[db_type], &reply, "file",
                                                    database_collection_name, NULL);
            break;
        default:
            break;
    }

    if (send_result && reply[0]->status==STATUS_OK) {
        char message_db_name_field[DB_COLLECTION_NAME_SIZE];
        snprintf(message_db_name_field, DB_COLLECTION_NAME_SIZE, "%s_database", collection_names[db_type]);
        // TODO switch to normal json library
        if (parse_json_data(reply[0]->data, message_db_name_field, result_db_data_buf, result_db_data_buf_size) ==
            XCASH_OK) {
            if (strncmp(result_db_data_buf, DATABASE_EMPTY_STRING, BUFFER_SIZE) == 0) {
                WARNING_PRINT("reply contains empty database");
            } else {
                // FIXME it's an original hack for fkn old json parser
                result_db_data_buf[strlen(result_db_data_buf) - 2] = '\0';
            }
            result = true;
        } else {
            ERROR_PRINT("Could't parse '%s' from reply", message_db_name_field);
        }
    }

    cleanup_responses(reply);
    return result;
}

void cleanup_db_sync_results(xcash_db_sync_obj_t **sync_objs_result) {
    if (sync_objs_result != NULL) {
        for (size_t i = 0; sync_objs_result[i] != NULL; i++) {
            free(sync_objs_result[i]->sync_records);
            free(sync_objs_result[i]);
        }
        free(sync_objs_result);
    }
}

size_t get_db_sub_count(xcash_dbs_t db_type) {
    size_t dbs_count = 0;
    switch (db_type) {
        case XCASH_DB_DELEGATES:
            dbs_count = 0;
            break;
        case XCASH_DB_STATISTICS:
            dbs_count = 0;
            break;
        case XCASH_DB_RESERVE_PROOFS:
            dbs_count = TOTAL_RESERVE_PROOFS_DATABASES;
            break;
        case XCASH_DB_RESERVE_BYTES:
            // TODO replace to my own function
            get_reserve_bytes_database(dbs_count, 0);
            break;
        default:
            break;
    }
    return dbs_count;
}

bool send_db_sync_request_to_all_seeds(xcash_dbs_t db_type, size_t start_db_index, response_t*** reply) {
    size_t dbs_count = get_db_sub_count(db_type);

    // TODO process start_db_index correctly for multi db sync
    // prepare parameters for sync update request
    // +3 it's +1 for reserve bytes setting param, +1 for overall hash, +1 NULL terminate parameter
    const char **param_list = calloc(dbs_count + 3, sizeof(char *) * 2);
    char(*hashes)[DB_HASH_SIZE + 1] = calloc(dbs_count + 1, DB_HASH_SIZE + 1);
    char(*collection_prefixes)[DB_COLLECTION_NAME_SIZE] = calloc(dbs_count + 1, DB_COLLECTION_NAME_SIZE);

    bool all_set = true;
    const char **current_parameter = param_list;

    const char *reserve_bytes_settings_str = "reserve_bytes_settings";
    const char *reserve_bytes_settings_param_str = "0";

    for (size_t i = start_db_index; i <= dbs_count; i++) {
        // this part is for database names
        if (i > 0) {
            snprintf(collection_prefixes[i], DB_COLLECTION_NAME_SIZE, "%s_%ld", collection_names[db_type], i);
        } else {
            snprintf(collection_prefixes[i], DB_COLLECTION_NAME_SIZE, "%s", collection_names[db_type]);
        }

        if (!get_db_data_hash(collection_prefixes[i], hashes[i])) {
            ERROR_PRINT("Can't get hash for %s db", collection_prefixes[i]);
            all_set = false;
            break;
            ;
        }

        // TODO fix message format
        // fuck! stupid format!
        // this part is for field names
        if (i > 0) {
            snprintf(collection_prefixes[i], DB_COLLECTION_NAME_SIZE, "%s_data_hash_%ld", collection_names[db_type], i);
        } else {
            snprintf(collection_prefixes[i], DB_COLLECTION_NAME_SIZE, "%s_data_hash", collection_names[db_type]);
        }

        if (i == 0 && db_type == XCASH_DB_RESERVE_BYTES) {
            *current_parameter++ = reserve_bytes_settings_str;
            *current_parameter++ = reserve_bytes_settings_param_str;
        }

        *current_parameter++ = (char *)&collection_prefixes[i];
        *current_parameter++ = (char *)&hashes[i];
    }

    if (!all_set) {
        free(param_list);
        free(hashes);
        free(collection_prefixes);
        return false;
    }

    bool send_result =
        send_message_param_list(XNET_SEEDS_ALL_ONLINE, xcash_db_sync_messages[db_type], reply, param_list);

    // cleanup
    free(param_list);
    free(hashes);
    free(collection_prefixes);

    return send_result;
}




bool send_db_sync_request_from_host(const char* sync_source_host, xcash_dbs_t db_type, size_t start_db_index, response_t*** reply) {
    size_t dbs_count = get_db_sub_count(db_type);

    // prepare parameters for sync update request
    // +3 it's +1 for reserve bytes setting param, +1 for overall hash, +1 NULL terminate parameter
    const char **param_list = calloc(dbs_count + 3, sizeof(char *) * 2);
    char(*hashes)[DB_HASH_SIZE + 1] = calloc(dbs_count + 1, DB_HASH_SIZE + 1);
    char(*collection_prefixes)[DB_COLLECTION_NAME_SIZE] = calloc(dbs_count + 1, DB_COLLECTION_NAME_SIZE);

    bool all_set = true;
    const char **current_parameter = param_list;

    const char *reserve_bytes_settings_str = "reserve_bytes_settings";
    const char *reserve_bytes_settings_param_str = "0";

    for (size_t i = start_db_index; i <= dbs_count; i++) {
        // this part is for database names
        if (i > 0) {
            snprintf(collection_prefixes[i], DB_COLLECTION_NAME_SIZE, "%s_%ld", collection_names[db_type], i);
        } else {
            snprintf(collection_prefixes[i], DB_COLLECTION_NAME_SIZE, "%s", collection_names[db_type]);
        }

        if (!get_db_data_hash(collection_prefixes[i], hashes[i])) {
            ERROR_PRINT("Can't get hash for %s db", collection_prefixes[i]);
            all_set = false;
            break;
            ;
        }

        // TODO fix message format
        // fuck! stupid format!
        // this part is for field names
        if (i > 0) {
            snprintf(collection_prefixes[i], DB_COLLECTION_NAME_SIZE, "%s_data_hash_%ld", collection_names[db_type], i);
        } else {
            snprintf(collection_prefixes[i], DB_COLLECTION_NAME_SIZE, "%s_data_hash", collection_names[db_type]);
        }

        if (i == 0 && db_type == XCASH_DB_RESERVE_BYTES) {
            *current_parameter++ = reserve_bytes_settings_str;
            *current_parameter++ = reserve_bytes_settings_param_str;
        }

        *current_parameter++ = (char *)&collection_prefixes[i];
        *current_parameter++ = (char *)&hashes[i];
    }

    if (!all_set) {
        free(param_list);
        free(hashes);
        free(collection_prefixes);
        return false;
    }

    bool send_result =
        send_direct_message_param_list(sync_source_host, xcash_db_sync_messages[db_type], reply, param_list);

    // cleanup
    free(param_list);
    free(hashes);
    free(collection_prefixes);

    return send_result;
}



bool check_multi_db_hashes_from_host(const char* sync_source_host, xcash_dbs_t db_type, xcash_db_sync_obj_t ***sync_objs_result) {
    bool result = false;
    *sync_objs_result = NULL;
    response_t **replies = NULL;

    bool send_result = send_db_sync_request_from_host(sync_source_host, db_type, 0, &replies);

    // now prepare sync statuses
    if (send_result) {
        result = parse_nodes_sync_reply(replies, db_type, sync_objs_result);
    }
    cleanup_responses(replies);
    
    return result;
}


// TODO obsolete
// bool check_multi_db_hashes_from_seeds(xcash_dbs_t db_type, xcash_db_sync_obj_t ***sync_objs_result) {
//     bool result = false;
//     *sync_objs_result = NULL;

//     response_t **replies;
//     bool send_result = send_db_sync_request_to_all_seeds(db_type, 0, &replies);

//     // now prepare sync statuses
//     if (send_result) {
//         result = parse_nodes_sync_reply(replies, db_type, sync_objs_result);
//     }
//     cleanup_responses(replies);

//     return result;
// }

size_t get_replies_count(response_t** const replies) {
    size_t i = 0;
    while(replies && replies[i]) i++;
    return i;
}

bool parse_nodes_sync_reply(response_t** replies, xcash_dbs_t db_type, xcash_db_sync_obj_t ***sync_objs_result) {
    char db_data_buf[BUFFER_SIZE];
    char db_field_name[DB_COLLECTION_NAME_SIZE];
    memset(db_data_buf, 0, sizeof(db_data_buf));
    bool result = false;

    size_t dbs_count = get_db_sub_count(db_type);
    size_t nodes_count = get_replies_count(replies);

    xcash_db_sync_obj_t **db_sync_status = calloc(nodes_count + 1, sizeof(xcash_db_sync_obj_t *));

    for (size_t node_index = 0, online_node_index = 0; node_index < nodes_count; node_index++) {
        if ((replies[node_index]->status==STATUS_OK) &&  (replies[node_index]->data)) {
            // DEBUG_PRINT("%s",replies[node_index]->data);
            db_sync_status[online_node_index] = calloc(1, sizeof(xcash_db_sync_obj_t));
            // init sync records for each node that replied
            // fill only online nodes info
            db_sync_status[online_node_index]->db_node_index = node_index;
            db_sync_status[online_node_index]->records_count = dbs_count + 1;
            db_sync_status[online_node_index]->db_synced = true;
            db_sync_status[online_node_index]->sync_records = (xcash_dbs_check_status_t *)calloc(
                db_sync_status[online_node_index]->records_count, sizeof(xcash_dbs_check_status_t));

            // TODO for reserve bytes we need flexible checker for only last records. because of big amounts
            // just for simplicity
            xcash_dbs_check_status_t *current_db_sync_records = db_sync_status[online_node_index]->sync_records;
            for (size_t db_rec_index = 0; db_rec_index < db_sync_status[online_node_index]->records_count;
                 db_rec_index++) {
                // TODO fix message format and move to normal json parser
                if (db_rec_index == 0) {
                    snprintf(db_field_name, DB_COLLECTION_NAME_SIZE, "%s_database", collection_names[db_type]);
                } else {
                    snprintf(db_field_name, DB_COLLECTION_NAME_SIZE, "%s_database_%ld", collection_names[db_type],
                             db_rec_index);
                }

                if (parse_json_data(replies[node_index]->data, db_field_name, db_data_buf, sizeof(db_data_buf)) ==
                    XCASH_ERROR) {
                    DEBUG_PRINT("Can't parse json answer %s", replies[node_index]->data);
                    db_sync_status[node_index]->db_synced = false;
                    continue;
                }

                // save db_rec_index in statuses, we need it for partial checks later
                current_db_sync_records[db_rec_index].db_rec_index = db_rec_index;
                if (strncmp(db_data_buf, "false", DB_COLLECTION_NAME_SIZE) == 0) {
                    // TODO fuck again. server always returns false for reserve proofs 'global' hash
                    // check only real databases not global hash

                    if ((db_type == XCASH_DB_RESERVE_PROOFS) || (db_type == XCASH_DB_RESERVE_BYTES)) {
                        if (db_rec_index != 0) {
                            db_sync_status[online_node_index]->db_synced = false;
                        }
                    } else {
                        db_sync_status[online_node_index]->db_synced = false;
                    }
                    current_db_sync_records[db_rec_index].db_rec_synced = false;
                } else {
                    current_db_sync_records[db_rec_index].db_rec_synced = true;
                }
            }
            online_node_index++;
            // if at least one response, then we have sync status
            // but we need to cleanup memory in all cases
            result = true;
        }
    }

    *sync_objs_result = db_sync_status;

    return result;
}

bool check_db_hashes_from_seeds(xcash_dbs_t db_type, xcash_db_sync_obj_t ***sync_objs_result) {
    bool result = false;

    char hash_buffer[DB_HASH_SIZE + 1];
    response_t **replies = NULL;

    *sync_objs_result = NULL;

    memset(hash_buffer, 0, sizeof(hash_buffer));

    if (!get_db_data_hash(collection_names[db_type], hash_buffer)) {
        ERROR_PRINT("Can't get hash for %s db", collection_names[db_type]);
        return false;
    }

    bool send_result = send_message_param(XNET_SEEDS_ALL_ONLINE, xcash_db_sync_messages[db_type], &replies, "data_hash",
                                          hash_buffer, NULL);

    if (send_result) {
        result = parse_nodes_sync_reply(replies, db_type, sync_objs_result);
        cleanup_responses(replies);
    }

    return result;
}

bool check_db_has_majority(xcash_dbs_t db_type, xcash_db_sync_obj_t **sync_objs) {
    bool result = false;
    if (sync_objs) {
        size_t majority_count = 0;
        for (size_t i = 0; sync_objs[i] != NULL; i++) {
            if (sync_objs[i]->db_synced) {
                majority_count++;
                INFO_PRINT(HOST_OK_STATUS("%s", " hash matched"),
                           network_data_nodes_list.network_data_nodes_IP_address[sync_objs[i]->db_node_index]);
            } else {
                INFO_PRINT(HOST_FALSE_STATUS("%s", "hash NOT matched"),
                           network_data_nodes_list.network_data_nodes_IP_address[sync_objs[i]->db_node_index]);
            }
        }
        if (majority_count >= NETWORK_DATA_NODES_VALID_AMOUNT) {
            INFO_PRINT(HOST_OK_STATUS("%s", "database has majority"), collection_names[db_type]);
            result = true;
        }
    }
    return result;
}


// TODO now it's obsolete
// bool sync_multi_db_from_node(const char* public_address, xcash_dbs_t db_type) {
//     xcash_db_sync_obj_t **sync_objs = NULL;
//     bool result = false;
//     // FIXME convert public_address to index
//     xcash_seed_idx_t sync_source_node_index;

//     if (!check_multi_db_hashes_from_seeds(db_type, &sync_objs)) {
//         WARNING_PRINT("Can't find source for %s db sync", collection_names[db_type]);

//         cleanup_db_sync_results(sync_objs);
//         return false;
//     }

//     if (check_db_has_majority(db_type, sync_objs)) {
//         cleanup_db_sync_results(sync_objs);
//         return true;
//     } else {
//         // TODO check majority by comparing all checked statuses from all nodes

//         size_t dbs_count = get_db_sub_count(db_type);
//         bool *dbs_to_update = (bool *)calloc(dbs_count + 1, sizeof(bool));

//         size_t total_answers = 0;
//         size_t synced_answers = 0;

//         for (size_t i = 0; sync_objs[i] != NULL; i++) {
//             xcash_dbs_check_status_t *sync_records = sync_objs[i]->sync_records;
//             total_answers++;
//             if (sync_objs[i]->db_synced) synced_answers++;

//             INFO_PRINT("Comparing node %s ",
//                        network_data_nodes_list.network_data_nodes_IP_address[sync_objs[i]->db_node_index]);
//             for (size_t rec_index = 0; rec_index < sync_objs[i]->records_count; rec_index++) {
//                 if (!sync_records[rec_index].db_rec_synced) {
//                     if (sync_records[rec_index].db_rec_index != 0) {
//                         INFO_PRINT(HOST_FALSE_STATUS("%s_%ld", "hash NOT matched"), collection_names[db_type],
//                                    sync_records[rec_index].db_rec_index);
//                         dbs_to_update[sync_records[rec_index].db_rec_index] = true;
//                     } else {
//                         // anyway the zero index always wrong
//                         // INFO_PRINT(HOST_FALSE_STATUS("%s", "hash NOT matched"), collection_names[db_type]);
//                     }
//                 }
//             }
//         }

//         if (total_answers == synced_answers) {
//             WARNING_PRINT("%s database has no majority, but we have no choice", collection_names[db_type]);
//             result = true;

//             free(dbs_to_update);
//             cleanup_db_sync_results(sync_objs);
//         } else {
//             char *db_data_buf = (char *)calloc(MAXIMUM_BUFFER_SIZE,1);
//             if (db_data_buf == NULL) {
//                 FATAL_ERROR_EXIT("Memory allocation failed");
//             }

//             bool updated_applied = true;
//             for (size_t db_file_index = 0; db_file_index <= dbs_count; db_file_index++) {
//                 if (dbs_to_update[db_file_index] == true) {
//                     INFO_PRINT("Updating %s_%ld database from %s ", collection_names[db_type], db_file_index,
//                                network_data_nodes_list.network_data_nodes_IP_address[sync_source_node_index]);

//                     if (!download_db_from_node(
//                             network_data_nodes_list.network_data_nodes_IP_address[sync_source_node_index], db_type,
//                             db_file_index, db_data_buf, MAXIMUM_BUFFER_SIZE)) {
//                         ERROR_PRINT("Can't download %s database", collection_names[db_type]);
//                         updated_applied = false;
//                         break;
//                     }
//                     // TODO add db index for multi dbs
//                     // TODO remove dependencies of global variables
//                     if (upsert_json_to_db(database_name, db_type, db_file_index, db_data_buf, false) == XCASH_ERROR) {
//                         ERROR_PRINT("Can't upsert %s database", collection_names[db_type]);
//                         updated_applied = false;
//                         break;
//                     }
//                 }
//             }

//             free(db_data_buf);
//             free(dbs_to_update);

//             // update needed databases
//             cleanup_db_sync_results(sync_objs);

//             result = updated_applied;
//         }
//     }

//     return result;
// }

// // TODO now it's obsolete
// bool sync_mono_db_from_node(const char* public_address, xcash_dbs_t db_type) {
//     xcash_db_sync_obj_t **sync_objs = NULL;
//     bool result = false;
//     //FIXME: convert public address to index
//     xcash_seed_idx_t sync_source_node_index;

//     if (!check_db_hashes_from_seeds(db_type, &sync_objs)) {
//         WARNING_PRINT("Can't find source for %s db sync", collection_names[db_type]);
//         cleanup_db_sync_results(sync_objs);
//         return false;
//     }

//     if (check_db_has_majority(db_type, sync_objs)) {
//         cleanup_db_sync_results(sync_objs);
//         result = true;
//     } else {
//         // if synced answers == total answers, then we have sync status.
//         // it's just not to sync each time then most nodes are offline

//         size_t total_answers = 0;
//         size_t synced_answers = 0;

//         for (size_t i = 0; sync_objs[i] != NULL; i++) {
//             total_answers++;
//             if (sync_objs[i]->db_synced) synced_answers++;
//         }

//         // we don't need that structure anymore
//         cleanup_db_sync_results(sync_objs);

//         if (total_answers == synced_answers) {
//             WARNING_PRINT("%s database has no majority, but we have no choice", collection_names[db_type]);
//             result = true;
//         } else {
//             char *db_data_buf = (char *)calloc(MAXIMUM_BUFFER_SIZE,1);
//             if (db_data_buf == NULL) {
//                 FATAL_ERROR_EXIT("Memory allocation failed");
//             }

//             INFO_PRINT("Updating %s database from %s ", collection_names[db_type],
//                        network_data_nodes_list.network_data_nodes_IP_address[sync_source_node_index]);

//             if (!download_db_from_node(network_data_nodes_list.network_data_nodes_IP_address[sync_source_node_index],
//                                        db_type, 0, db_data_buf, sizeof(db_data_buf))) {
//                 ERROR_PRINT("Can't download %s database", collection_names[db_type]);
//                 free(db_data_buf);
//                 return false;
//             }

//             // TODO remove dependencies of global variables
//             if (upsert_json_to_db(database_name, db_type, 0, db_data_buf, false) == XCASH_ERROR) {
//                 ERROR_PRINT("Can't upsert %s database", collection_names[db_type]);
//                 free(db_data_buf);
//                 return false;
//             }

//             free(db_data_buf);
//             result = true;
//         }
//     }

//     return result;
// }

bool update_multi_db_from_node(const char* public_address, xcash_dbs_t db_type) {
    bool result = false;
    xcash_db_sync_obj_t **sync_objs = NULL;

    const char* update_source_host = address_to_node_host(public_address);
    if (!update_source_host) {
        ERROR_PRINT("Something is wrong. The address %s not found in current block verifiers, nor the seeds", public_address);
        return false;
    }

    INFO_PRINT("Looking for not synced parts in %s database ", collection_names[db_type]);

    if (!check_multi_db_hashes_from_host(update_source_host, db_type, &sync_objs)) {
        WARNING_PRINT("Can't find source for %s db sync", collection_names[db_type]);

        cleanup_db_sync_results(sync_objs);
        return false;
    }

    size_t dbs_count = get_db_sub_count(db_type);
    bool *dbs_to_update = (bool *)calloc(dbs_count + 1, sizeof(bool));

    for (size_t i = 0; sync_objs[i] != NULL; i++) {
        xcash_dbs_check_status_t *sync_records = sync_objs[i]->sync_records;
        for (size_t rec_index = 0; rec_index < sync_objs[i]->records_count; rec_index++) {
            if (!sync_records[rec_index].db_rec_synced) {
                if (sync_records[rec_index].db_rec_index != 0) {
                    INFO_PRINT(HOST_FALSE_STATUS("%s_%ld", "hash does NOT match"), collection_names[db_type],
                                sync_records[rec_index].db_rec_index);
                    dbs_to_update[sync_records[rec_index].db_rec_index] = true;
                } else {
                    // anyway the zero index always wrong
                    // INFO_PRINT(HOST_FALSE_STATUS("%s", "hash NOT matched"), collection_names[db_type]);
                }
            }
        }
    }

    char *db_data_buf = (char *)calloc(MAXIMUM_BUFFER_SIZE,1);
    if (db_data_buf == NULL) {
        FATAL_ERROR_EXIT("Memory allocation failed");
    }

    bool updated_applied = true;
    for (size_t db_file_index = 0; db_file_index <= dbs_count; db_file_index++) {
        if (dbs_to_update[db_file_index] == true) {
            INFO_PRINT("Updating %s_%ld database from %s ", collection_names[db_type], db_file_index, update_source_host);

            if (!download_db_from_node(update_source_host, db_type, db_file_index, db_data_buf, MAXIMUM_BUFFER_SIZE)) {
                ERROR_PRINT("Can't download %s database", collection_names[db_type]);
                updated_applied = false;
                break;
            }
            // TODO remove dependencies of global variables
            if (upsert_json_to_db(database_name, db_type, db_file_index, db_data_buf, false) == XCASH_ERROR) {
                ERROR_PRINT("Can't upsert %s database", collection_names[db_type]);
                updated_applied = false;
                break;
            }
        }
    }

    free(db_data_buf);
    free(dbs_to_update);

    // update needed databases
    cleanup_db_sync_results(sync_objs);

    result = updated_applied;

    return result;
}


bool update_db_from_node(const char* public_address, xcash_dbs_t db_type) {
    const char* update_source_host = address_to_node_host(public_address);
    if (!update_source_host) {
        ERROR_PRINT("Something is wrong. The address %s not found in current block verifiers, nor the seeds", public_address);
        return false;
    }

    INFO_PRINT("Updating %s database from %s ", collection_names[db_type], update_source_host);

    char* db_data_buf = calloc(MAXIMUM_BUFFER_SIZE, 1);

    if (!download_db_from_node(update_source_host, db_type, 0, db_data_buf, MAXIMUM_BUFFER_SIZE)) {
        ERROR_PRINT("Can't download %s database", collection_names[db_type]);
        free(db_data_buf);
        return false;
    }

    // TODO remove dependencies of global variables
    if (upsert_json_to_db(database_name, db_type, 0, db_data_buf, false) == XCASH_ERROR) {
        ERROR_PRINT("Can't upsert %s database", collection_names[db_type]);
        free(db_data_buf);
        return false;
    }

    free(db_data_buf);
    return true;
}


// TODO obsolete
// bool sync_update_db_from_node(const char* public_address, xcash_dbs_t db_type) {
//     bool result = false;

//     INFO_STAGE_PRINT("Syncing %s db", collection_names[db_type]);

//     switch (db_type) {
//         case XCASH_DB_DELEGATES:
//         case XCASH_DB_STATISTICS:
//             result = sync_mono_db_from_node(public_address, db_type);
//             break;
//         case XCASH_DB_RESERVE_PROOFS:
//         case XCASH_DB_RESERVE_BYTES:
//             result = sync_multi_db_from_node(public_address, db_type);
//             break;
//         default:
//             break;
//     }

//     return result;
// }


bool initial_sync_node(xcash_node_sync_info_t* majority_source) {
    xcash_dbs_t sync_db;
    xcash_node_sync_info_t sync_info;

    INFO_STAGE_PRINT("Checking the node DB sync status");

    if (!get_node_sync_info(&sync_info)) {
        ERROR_PRINT("Can't get local sync info");
        return false;
    }



    // FIXME this mean we definitely need to sync the node
    if (sync_info.block_height != majority_source->block_height) {
        WARNING_PRINT("The local node has a block height %ld vs majority %ld, which differs from the majority", sync_info.block_height, majority_source->block_height);
        // return false;
    }

    for (size_t i = 0; i < DATABASE_TOTAL; i++)
    {
        sync_db = (xcash_dbs_t)i;
        if (strcmp(sync_info.db_hashes[i], majority_source->db_hashes[i]) == 0){
            INFO_PRINT(HOST_OK_STATUS("%s", "db synced"), collection_names[sync_db]);
            continue;
        }

        INFO_STAGE_PRINT("Syncing %s db", collection_names[sync_db]);

        bool sync_result = false;
        switch (sync_db) {
        case XCASH_DB_DELEGATES:
        case XCASH_DB_STATISTICS:
            sync_result = update_db_from_node(majority_source->public_address, sync_db);
            break;
        case XCASH_DB_RESERVE_PROOFS:
        case XCASH_DB_RESERVE_BYTES:
            sync_result = update_multi_db_from_node(majority_source->public_address, sync_db);
            break;
        default:
            break;
        }

        if (sync_result) {
            INFO_PRINT(HOST_OK_STATUS("%s", "db synced"), collection_names[sync_db]);
        }else{
            WARNING_PRINT("Can't sync db %s", collection_names[sync_db]);
            return false;
        }
    }
    return true;
}




// get all nodes from local db
bool get_nodes_from_db(void) {
    delegates_t* delegates = (delegates_t*)calloc(MAXIMUM_AMOUNT_OF_DELEGATES, sizeof(delegates_t));
    size_t total_delegates = 0;


    // TODO probably, if the db is brand new, we should fill at least the nodes information

    if (read_organize_delegates(delegates, &total_delegates) != XCASH_OK) {
        ERROR_PRINT("Could not organize the delegates");

        free(delegates);
        return false;
    }

    total_delegates = total_delegates > BLOCK_VERIFIERS_TOTAL_AMOUNT ? BLOCK_VERIFIERS_TOTAL_AMOUNT: total_delegates;


    block_verifiers_list_t *block_verifiers_list[] = {
        &previous_block_verifiers_list,
        &current_block_verifiers_list,
        &next_block_verifiers_list,
    };


    // FIXME: it could be much easier, but i need to change all structures everywhere
    for (size_t i = 0; i < total_delegates; i++)
    {
        for(size_t type_index = 0; type_index < sizeof(block_verifiers_list)/sizeof(block_verifiers_list_t*); type_index++) {
            strncpy(block_verifiers_list[type_index]->block_verifiers_name[i], delegates[i].delegate_name, sizeof(block_verifiers_list[type_index]->block_verifiers_name[i]));
            strncpy(block_verifiers_list[type_index]->block_verifiers_public_address[i], delegates[i].public_address, sizeof(block_verifiers_list[type_index]->block_verifiers_public_address[i]));
            strncpy(block_verifiers_list[type_index]->block_verifiers_public_key[i], delegates[i].public_key, sizeof(block_verifiers_list[type_index]->block_verifiers_public_key[i]));
            strncpy(block_verifiers_list[type_index]->block_verifiers_IP_address[i], delegates[i].IP_address, sizeof(block_verifiers_list[type_index]->block_verifiers_IP_address[i]));
        }
    }

    // cleanup the allocated memory
    free(delegates);

    return true;
}



bool fill_delegates_from_db(void) {
    delegates_t* delegates = (delegates_t*)calloc(MAXIMUM_AMOUNT_OF_DELEGATES, sizeof(delegates_t));
    size_t total_delegates = 0;

    if (read_organize_delegates(delegates, &total_delegates) != XCASH_OK) {
        ERROR_PRINT("Could not organize the delegates");

        free(delegates);
        return false;
    }

    total_delegates = total_delegates > BLOCK_VERIFIERS_TOTAL_AMOUNT ? BLOCK_VERIFIERS_TOTAL_AMOUNT: total_delegates;

    // fill actual list of all delegates from db
    for (size_t i = 0; i < BLOCK_VERIFIERS_TOTAL_AMOUNT; i++)
    {
        if (i< total_delegates) {
            delegates_all[i] = delegates[i];
        }else {
            memset(&delegates_all[i], 0, sizeof(delegates_t));
        }
    }
    

    // cleanup the allocated memory
    free(delegates);

    return true;
}


bool parse_node_list_data(const char* message_data) {
    char parse_tmp_buf[BUFFER_SIZE];

    char * key_names[] = {
        "block_verifiers_name_list",
        "block_verifiers_public_address_list",
        "block_verifiers_public_key_list",
        "block_verifiers_IP_address_list",
    };
    enum key_names_id {
        BLOCK_VERIFIERS_NAME_LIST = 0,
        BLOCK_VERIFIERS_PUBLIC_ADDRESS_LIST,
        BLOCK_VERIFIERS_PUBLIC_KEY_LIST,
        BLOCK_VERIFIERS_IP_ADDRESS_LIST,
    };

    char * type_key_names[] = {
        "previous",
        "current",
        "next",
    };

    block_verifiers_list_t *block_verifiers_list[] = {
        &previous_block_verifiers_list,
        &current_block_verifiers_list,
        &next_block_verifiers_list,
    };

    char parser_key_name[256];

    bool parse_result = true;
    for(size_t type_index = 0; parse_result && type_index < sizeof(type_key_names)/sizeof(char*); type_index++) {
        for (size_t key_index = 0; key_index < sizeof(key_names)/sizeof(char*); key_index++)
        {
            snprintf(parser_key_name, sizeof(parser_key_name), "%s_%s", type_key_names[type_index], key_names[key_index]);

            // FIXME switch to normal json parser
            memset(parse_tmp_buf,0, sizeof(parse_tmp_buf));
            if (parse_json_data(message_data,parser_key_name,parse_tmp_buf,sizeof(parse_tmp_buf)) == 0) 
            { 
                ERROR_PRINT("Error parsing JSON message. '%s' key", parser_key_name);
                parse_result = false;
                break;
            }
            char **key_values_list = NULL;
            int element_count = split(parse_tmp_buf,'|', &key_values_list);
            if (element_count < 0) {
                ERROR_PRINT("Can't split elements in '%s' key", parser_key_name);
                parse_result = false;
                break;
            }

            for (int element_index = 0; element_index < element_count; element_index++) {
                switch (key_index) {
                    case BLOCK_VERIFIERS_NAME_LIST:
                        strncpy(block_verifiers_list[type_index]->block_verifiers_name[element_index],
                                key_values_list[element_index],
                                sizeof(block_verifiers_list[type_index]->block_verifiers_name[element_index]));
                        break;

                    case BLOCK_VERIFIERS_PUBLIC_ADDRESS_LIST:
                        strncpy(
                            block_verifiers_list[type_index]->block_verifiers_public_address[element_index],
                            key_values_list[element_index],
                            sizeof(block_verifiers_list[type_index]->block_verifiers_public_address[element_index]));
                        break;

                    case BLOCK_VERIFIERS_PUBLIC_KEY_LIST:
                        strncpy(block_verifiers_list[type_index]->block_verifiers_public_key[element_index],
                                key_values_list[element_index],
                                sizeof(block_verifiers_list[type_index]->block_verifiers_public_key[element_index]));
                        break;

                    case BLOCK_VERIFIERS_IP_ADDRESS_LIST:
                        strncpy(block_verifiers_list[type_index]->block_verifiers_IP_address[element_index],
                                key_values_list[element_index],
                                sizeof(block_verifiers_list[type_index]->block_verifiers_IP_address[element_index]));
                        break;

                    default:
                        break;
                }
            }
            cleanup_char_list(key_values_list);
        }
    }

    return parse_result;
}

bool get_nodes_from_seed(void) {
    bool result = false;
    response_t** reply;
    bool send_result = send_message(XNET_SEEDS_ALL_ONLINE, XMSG_NODE_TO_NETWORK_DATA_NODES_GET_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST, &reply);
    if (send_result && reply) {
        for (size_t i = 0; reply[i]!=NULL; i++)
        {
            if (reply[i]->status == STATUS_OK) {
                // DEBUG_PRINT("%s", reply[i]->data);
                if (!parse_node_list_data(reply[i]->data)) {
                    ERROR_PRINT("Can't parse node list from seed %s", reply[i]->host);
                    continue;
                }
                result = true;
                break;
            }
        }
        cleanup_responses(reply);
    }
    return result;
}

bool get_actual_nodes_list(bool is_seeds_offline) {
    bool result = false;

    INFO_STAGE_PRINT("Loading actual nodes list");

    // for all cases
    if (!fill_delegates_from_db()) {
        ERROR_PRINT("Can't read delegates from db");
    }

    if (is_seeds_offline){
        INFO_PRINT("Seed nodes offline. Getting delegates list from local db");
        result = get_nodes_from_db();
        if (result) {
            INFO_PRINT("All nodes list loaded from the local database");
        }

    }else{
        INFO_PRINT("Getting delegates list from seeds");
        result = get_nodes_from_seed();
        if (result) {
            INFO_PRINT("All nodes list loaded successfully");
        }
    }

    return result;
}


int compare_sync_hashed_node_data(const void* a, const void* b) {
    const xcash_db_sync_prehash_t* node1 = (const xcash_db_sync_prehash_t* )a;
    const xcash_db_sync_prehash_t* node2 = (const xcash_db_sync_prehash_t* )b;

    if (node1->sync_info->block_height > node2->sync_info->block_height) {
        return -1;
    } else if (node1->sync_info->block_height < node2->sync_info->block_height) {
        return 1;
    }

    return strcmp(node1->overall_md5_hash, node2->overall_md5_hash);
}

xcash_node_sync_info_t** make_nodes_majority_list(xcash_node_sync_info_t* sync_states_list, size_t states_count, bool by_top_block_height) {
    // last pointer in sync_states_sorted_list is NULL as the marker of the end of the list
    xcash_node_sync_info_t** sync_states_sorted_list = calloc(states_count+1, sizeof(xcash_node_sync_info_t*));
    xcash_db_sync_prehash_t* sync_states_hashed_list = calloc(states_count, sizeof(xcash_db_sync_prehash_t));
    

    if (!sync_states_sorted_list || !sync_states_hashed_list) {
        FATAL_ERROR_EXIT("Can't allocate sync_states_sorted_list memory");
    }

    // make enough space for overall hash data
    char common_data[DATA_HASH_LENGTH*(DATABASE_TOTAL+1)];
    for (size_t i = 0; i < states_count; i++)
    {
        sync_states_hashed_list[i].sync_info = &sync_states_list[i];
        sprintf(common_data, "%s%s%s%s%ld", sync_states_list[i].db_hashes[0], sync_states_list[i].db_hashes[1],
                sync_states_list[i].db_hashes[2], sync_states_list[i].db_hashes[3], sync_states_list[i].block_height);

        md5_hex(common_data, sync_states_hashed_list[i].overall_md5_hash);
    }
    
    qsort(sync_states_hashed_list, states_count, sizeof(xcash_db_sync_prehash_t), compare_sync_hashed_node_data);

    // Now let's find a majority 
    int max_count = 0, current_count = 1;
    const char *major_hash = sync_states_hashed_list[0].overall_md5_hash;
    size_t top_block_height = sync_states_hashed_list[0].sync_info->block_height;
    for (size_t i = 1; i < states_count; i++) {
        if (strcmp(sync_states_hashed_list[i].overall_md5_hash, sync_states_hashed_list[i-1].overall_md5_hash) == 0) {
            current_count++;
            if (current_count > max_count) {
                max_count = current_count;
                major_hash = sync_states_hashed_list[i].overall_md5_hash;
            }
        } else {
            if (by_top_block_height && (sync_states_hashed_list[i].sync_info->block_height < top_block_height)) {
                break;
            }
            current_count = 1;
        }
    }

    // store to the result list only majority nodes
    for (size_t i = 0, major_index = 0; i < states_count; i++)
    {
        if (strcmp(sync_states_hashed_list[i].overall_md5_hash, major_hash) == 0) {
            sync_states_sorted_list[major_index] = sync_states_hashed_list[i].sync_info;
            major_index++;
        };
    }

    free(sync_states_hashed_list);

    return sync_states_sorted_list;
}


void show_majority_statistics(xcash_node_sync_info_t* majority_list, size_t items_count) {
    if (majority_list && items_count > 0) {
        INFO_STAGE_PRINT("Nodes majority status");
        for (size_t i = 0; i< items_count; i++)
        {
            INFO_PRINT_STATUS_OK("%-40s", address_to_node_name(majority_list[i].public_address));
        }
    } else {
        WARNING_PRINT("Empty majority list. Probably all other nodes are offline");
    }
}


bool get_sync_seeds_majority_list(xcash_node_sync_info_t** majority_list_result, size_t* majority_count_result) {
    bool result = false;
    *majority_list_result = NULL;
    *majority_count_result = 0;


    response_t** replies =  NULL;
    bool send_result = send_message(XNET_SEEDS_ALL, XMSG_XCASH_GET_SYNC_INFO, &replies);
    if (!send_result) {
        ERROR_PRINT("Can't get sync info from all delegates");
        cleanup_responses(replies);
    }

    xcash_node_sync_info_t* majority_list;
    size_t majority_count = 0;
    if (check_sync_nodes_majority_list(replies, &majority_list, &majority_count, false)) {
        result = true;
    }

    *majority_count_result =  majority_count;
    *majority_list_result = majority_list;

    // free(majority_list);
    cleanup_responses(replies);
    
    return result;    
}



bool get_sync_nodes_majority_list(xcash_node_sync_info_t** majority_list_result, size_t* majority_count_result) {
    bool result = false;
    *majority_list_result = NULL;
    *majority_count_result = 0;

    response_t** replies =  NULL;
    bool send_result = send_message(XNET_DELEGATES_ALL, XMSG_XCASH_GET_SYNC_INFO, &replies);
    if (!send_result) {
        ERROR_PRINT("Can't get sync info from all nodes");
        cleanup_responses(replies);
        return false;
    }

    xcash_node_sync_info_t* majority_list;
    size_t majority_count = 0;
    if (check_sync_nodes_majority_list(replies, &majority_list, &majority_count, false)) {
        result = true;
        // if (majority_count >= BLOCK_VERIFIERS_VALID_AMOUNT) {
        //     INFO_PRINT("Synced majority found. %ld nodes available", majority_count);
        //     result = true;
        // }
    }

    *majority_count_result =  majority_count;
    *majority_list_result = majority_list;


    cleanup_responses(replies);
    return result;
}


bool get_sync_nodes_majority_list_top(xcash_node_sync_info_t** majority_list_result, size_t* majority_count_result) {
    bool result = false;
    *majority_list_result = NULL;
    *majority_count_result = 0;

    response_t** replies =  NULL;
    bool send_result = send_message(XNET_DELEGATES_ALL, XMSG_XCASH_GET_SYNC_INFO, &replies);
    if (!send_result) {
        ERROR_PRINT("Can't get sync info from all nodes");
        cleanup_responses(replies);
        return false;
    }

    xcash_node_sync_info_t* majority_list;
    size_t majority_count = 0;
    if (check_sync_nodes_majority_list(replies, &majority_list, &majority_count, true)) {
        result = true;
    }

    *majority_count_result =  majority_count;
    *majority_list_result = majority_list;


    cleanup_responses(replies);
    return result;
}



bool check_sync_nodes_majority_list(response_t** replies,xcash_node_sync_info_t** majority_list_result, size_t* majority_count_result, bool by_top_block_height) {
    *majority_list_result = NULL;
    *majority_count_result = 0;
    // bool result = false;
    // count replies
    size_t num_replies = 0;
    for (size_t i = 0; replies && replies[i]; i++){
        if (replies[i]->status==STATUS_OK) 
            num_replies++;
    };

    if (num_replies == 0) {
        WARNING_PRINT("No valid replies received. Can't make majority sync list");
        // return empty list with 0 count
        return true;
    }

    xcash_node_sync_info_t* sync_states_list = calloc(num_replies, sizeof(xcash_node_sync_info_t));
    char parse_buffer[DATA_HASH_LENGTH+1];
    char record_name[DB_COLLECTION_NAME_SIZE];

    size_t sync_state_index = 0;
    for (size_t i = 0; replies[i] && sync_state_index<num_replies; i++){
        if (replies[i]->status==STATUS_OK) {
            memset(parse_buffer, 0, sizeof(parse_buffer));

            if (parse_json_data(replies[i]->data, "public_address", sync_states_list[sync_state_index].public_address, sizeof(sync_states_list[sync_state_index].public_address)) == 0) 
            {
                ERROR_PRINT("Can't parse 'public_address' reply from %s", replies[i]->host);
                // clean up the data, so if it will be the last it doesn't contains any garbage
                memset(&sync_states_list[sync_state_index], 0, sizeof(xcash_node_sync_info_t));
                continue;
            }

            if (parse_json_data(replies[i]->data, "block_height", parse_buffer, sizeof(parse_buffer)) == 0 ||
                sscanf(parse_buffer,"%zu", &(sync_states_list[sync_state_index].block_height)) !=1 ) 
            {
                ERROR_PRINT("Can't parse 'block_height' reply from %s", replies[i]->host);
                // clean up the data, so if it will be the last it doesn't contains any garbage
                memset(&sync_states_list[sync_state_index], 0, sizeof(xcash_node_sync_info_t));
                continue;
            }

            for (size_t db_i = 0; db_i < DATABASE_TOTAL; db_i++)
            {
                sprintf(record_name, "data_hash_%s",collection_names[db_i]);
                if (parse_json_data(replies[i]->data, record_name, sync_states_list[sync_state_index].db_hashes[db_i], sizeof(sync_states_list[sync_state_index].db_hashes[db_i])) == 0) 
                {
                    ERROR_PRINT("Can't parse '%s' reply from %s",record_name, replies[i]->host);
                    // clean up the data, so if it will be the last it doesn't contains any garbage
                    memset(&sync_states_list[sync_state_index], 0, sizeof(xcash_node_sync_info_t));
                    break;;
                }
            }
            sync_state_index++;
        }
    };

    // sync_state_index now contains the real parsed records count
    xcash_node_sync_info_t** sync_majority_list = make_nodes_majority_list(sync_states_list, sync_state_index, by_top_block_height);


    // calculate majority count
    int majority_count = 0;
    for (size_t i = 0; sync_majority_list[i]; i++, majority_count++){};


    // now make a fresh list of only majority sync statuses

    xcash_node_sync_info_t* majority_states_list = calloc(majority_count, sizeof(xcash_node_sync_info_t));
    for (size_t i = 0; sync_majority_list[i]; i++)
    {
        memcpy(&majority_states_list[i], sync_majority_list[i], sizeof(xcash_node_sync_info_t));
    }
    
    // set results
    *majority_count_result =  majority_count;
    *majority_list_result = majority_states_list;

    // cleanup
    free(sync_majority_list);
    free(sync_states_list);
    return true;
}


int get_random_majority(xcash_node_sync_info_t* majority_list, size_t majority_count) {
    int result =  0;
    int random_index;

    while (majority_count>0)
    {
        random_index = rand() % majority_count;

        // prevent syncing from myself
        if (strcmp(xcash_wallet_public_address, majority_list[random_index].public_address ) != 0) {
            result = random_index;
            break;
        }
    }
    return result;
}

size_t count_seeds_in_majority_list(xcash_node_sync_info_t* majority_list, size_t majority_count) {
    size_t result = 0;
    for (size_t i = 0; i < majority_count; i++)
    {
        if (is_seed_address(majority_list[i].public_address)) {
            result ++;
        }
    }
    return result;
}


/// @brief Check data integrity and return majority_list and count of majority_list nodes
/// @param majority_count 
/// @param majority_list_result optional. if NULL, the list will be freed internally
/// @return true if some of majority reached  false - majority not reached or empty list
bool initial_db_sync_check(size_t* majority_count, xcash_node_sync_info_t** majority_list_result) {
    bool result = false;
    *majority_count = 0;

    // size_t seeds_majority_count = 0;

    xcash_node_sync_info_t* nodes_majority_list = NULL;
    size_t nodes_majority_count = 0;

    INFO_STAGE_PRINT("Checking the network data majority");

    if (!get_sync_nodes_majority_list(&nodes_majority_list, &nodes_majority_count)) {
        WARNING_PRINT("Could not get data majority nodes sync list");
    }else{
        // seeds_majority_count = count_seeds_in_majority_list(nodes_majority_list, nodes_majority_count);
    }

    show_majority_statistics(nodes_majority_list, nodes_majority_count);


    if ((nodes_majority_count < BLOCK_VERIFIERS_VALID_AMOUNT)) {
        INFO_PRINT_STATUS_FAIL("Not enough data majority. All Nodes: [%ld/%d]", nodes_majority_count, BLOCK_VERIFIERS_VALID_AMOUNT);
        result = false;
    } else {
        INFO_PRINT_STATUS_OK("Data majority reached. All Nodes: [%ld/%d]",  nodes_majority_count, BLOCK_VERIFIERS_VALID_AMOUNT);
        int sync_source_index = get_random_majority(nodes_majority_list, nodes_majority_count);
        result = initial_sync_node(&nodes_majority_list[sync_source_index]);

        *majority_count = nodes_majority_count;
    }


    // if (is_seed_node) {
    //     if ((nodes_majority_count < BLOCK_VERIFIERS_VALID_AMOUNT)) {
    //         INFO_PRINT_STATUS_FAIL("Not enough data majority. Seeds: [%ld/%d] All Nodes: [%ld/%d]", seeds_majority_count, NETWORK_DATA_NODES_VALID_AMOUNT, nodes_majority_count, BLOCK_VERIFIERS_VALID_AMOUNT);
    //         result = false;
    //     } else {
    //         INFO_PRINT_STATUS_OK("Data majority reached. Seeds: [%ld/%d] All Nodes: [%ld/%d]", seeds_majority_count, NETWORK_DATA_NODES_VALID_AMOUNT, nodes_majority_count, BLOCK_VERIFIERS_VALID_AMOUNT);

    //     // if (seeds_majority_count < NETWORK_DATA_NODES_VALID_AMOUNT) {
    //     //     INFO_PRINT_STATUS_FAIL("Not enough seeds data majority. [%ld/%d]", seeds_majority_count, NETWORK_DATA_NODES_VALID_AMOUNT);
    //     //     result = false;
    //     // } else {
    //     //     INFO_PRINT_STATUS_OK("Seed nodes data majority found. %ld nodes available to sync", seeds_majority_count);

    //         // FIXME Originally we need to sync only from seeds. But why? This is already decentralized behavior
    //         int sync_source_index = get_random_majority(nodes_majority_list, nodes_majority_count);

    //         result = initial_sync_node(&nodes_majority_list[sync_source_index]);
    
    //         *majority_count = nodes_majority_count;
    //     }
    // } else {
    //     // if ((nodes_majority_count < BLOCK_VERIFIERS_VALID_AMOUNT) && (seeds_majority_count < NETWORK_DATA_NODES_VALID_AMOUNT)) {
    //     if ((nodes_majority_count < BLOCK_VERIFIERS_VALID_AMOUNT)) {
    //         INFO_PRINT_STATUS_FAIL("Not enough data majority. Seeds: [%ld/%d] All Nodes: [%ld/%d]", seeds_majority_count, NETWORK_DATA_NODES_VALID_AMOUNT, nodes_majority_count, BLOCK_VERIFIERS_VALID_AMOUNT);
    //         result = false;
    //     } else {
    //         INFO_PRINT_STATUS_OK("Data majority reached. Seeds: [%ld/%d] All Nodes: [%ld/%d]", seeds_majority_count, NETWORK_DATA_NODES_VALID_AMOUNT, nodes_majority_count, BLOCK_VERIFIERS_VALID_AMOUNT);
    //         int sync_source_index = get_random_majority(nodes_majority_list, nodes_majority_count);
    //         result = initial_sync_node(&nodes_majority_list[sync_source_index]);

    //         *majority_count = nodes_majority_count;
    //     }
    // }

    if (!majority_list_result) {
        free(nodes_majority_list);
    } else{
        *majority_list_result = nodes_majority_list;
    }
    return result;
}

bool check_time_sync_to_seeds(void) {
    long long int node_time;
    char node_time_buf[SMALL_BUFFER_SIZE];
    bool result = false;
    response_t **replies=NULL;

    INFO_STAGE_PRINT("Checking node time comparing to seed nodes");

    bool send_result = send_message(
        XNET_SEEDS_ALL, XMSG_BLOCK_VERIFIERS_TO_NETWORK_DATA_NODE_BLOCK_VERIFIERS_CURRENT_TIME, &replies);

    bool all_nodes_offline = true;

    if (send_result && replies) {

        for (size_t i = 0; replies && i < NETWORK_DATA_NODES_AMOUNT; i++) {
            if (replies[i]->status== STATUS_OK) {
                // FIXME switch to normal json parsing
                if (parse_json_data(replies[i]->data, "current_time", node_time_buf, sizeof(node_time_buf)) == 0 ||
                    strncmp(node_time_buf, "", 1) == 0) {
                    DEBUG_PRINT("Can't parse 'current_time' reply from %s", replies[i]->host);
                    continue;
                }

                sscanf(node_time_buf, "%lld", &node_time);
                long time_diff = labs(replies[i]->req_time_start - node_time);

                if (time_diff <= BLOCK_VERIFIERS_SETTINGS) {
                    INFO_PRINT(HOST_OK_STATUS("%s", "time shift is %lds"), replies[i]->host, time_diff);
                    result = true;
                    all_nodes_offline =  false;
                } else {
                    INFO_PRINT(HOST_FALSE_STATUS("%s", "time shift is %lds"), replies[i]->host, time_diff);
                }
            }
        }
    }

    // if all nodes are offline, there is nobody to sync
    if (all_nodes_offline) {
        result = true;
    }

    cleanup_responses(replies);

    if (result) {
        INFO_PRINT_STATUS_OK("Time checked");
    }

    return result;
};

// bool synchronize_database_from_network_data_node(void) {
//     get_node_data();
//     color_print("Syncing the block verifiers list", "yellow");
//     sync_all_block_verifiers_list(1, 1);
//     color_print("Syncing the reserve bytes database", "yellow");
//     sync_reserve_bytes_database(2, 0, "");
//     color_print("Syncing the reserve proofs database", "yellow");
//     sync_reserve_proofs_database(2, "");
//     color_print("Syncing the delegates database", "yellow");
//     sync_delegates_database(2, "");
//     color_print("Syncing the statistics database", "yellow");
//     sync_statistics_database(2, "");
//     color_print("Successfully synced all databases", "yellow");
//     return true;
// }

// bool synchronize_database_from_specific_delegate(const char *delegate_ip) {
//     get_node_data();
//     color_print("Syncing the block verifiers list", "yellow");
//     sync_all_block_verifiers_list(1, 1);
//     color_print("Syncing the reserve bytes database", "yellow");
//     sync_reserve_bytes_database(0, 0, delegate_ip);
//     color_print("Syncing the reserve proofs database", "yellow");
//     sync_reserve_proofs_database(0, delegate_ip);
//     color_print("Syncing the delegates database", "yellow");
//     sync_delegates_database(0, delegate_ip);
//     color_print("Syncing the statistics database", "yellow");
//     sync_statistics_database(0, delegate_ip);
//     color_print("Successfully synced all databases", "yellow");
//     return true;
// }



bool init_db_from_seeds(void) {
    bool result = false;

    while (!result)
    {
        size_t nodes_majority_count = 0;
        xcash_node_sync_info_t* nodes_majority_list = NULL;
    
        INFO_STAGE_PRINT("Checking the network data majority");

        if (!get_daemon_data()) {
            WARNING_PRINT("Can't get daemon data. You need to start xcash daemon service before");
            return false;
        }

        if (!get_node_data()) {
            WARNING_PRINT("Can't get wallet data. You need to start xcash rpc wallet service before");
            return false;
        }


        if (!get_sync_seeds_majority_list(&nodes_majority_list, &nodes_majority_count)) {
            WARNING_PRINT("Could not get data majority nodes sync list");
        }else{
            show_majority_statistics(nodes_majority_list, nodes_majority_count);

            if ((nodes_majority_count < NETWORK_DATA_NODES_VALID_AMOUNT)) {
                INFO_PRINT_STATUS_FAIL("Not enough data majority. Nodes: [%ld/%d]", nodes_majority_count, NETWORK_DATA_NODES_VALID_AMOUNT);
                result = false;
            } else {
                INFO_PRINT_STATUS_OK("Data majority reached. Nodes: [%ld/%d]",  nodes_majority_count, NETWORK_DATA_NODES_VALID_AMOUNT);
                int sync_source_index = get_random_majority(nodes_majority_list, nodes_majority_count);
                result = initial_sync_node(&nodes_majority_list[sync_source_index]);
            }
        }
        free(nodes_majority_list);

        if (!result) {
            INFO_STAGE_PRINT("Waiting for network recovery...");
            sleep(10);
        };
    }
    if (result) {
        INFO_PRINT_STATUS_OK("Database successfully synced")
    }

    return result;
}

bool init_db_from_top(void) {
    bool result = false;

    while (!result)
    {
        size_t nodes_majority_count = 0;
        xcash_node_sync_info_t* nodes_majority_list = NULL;
    
        INFO_STAGE_PRINT("Checking the network data majority");

        if (!get_daemon_data()) {
            WARNING_PRINT("Can't get daemon data. You need to start xcash daemon service before");
            return false;
        }

        if (!get_node_data()) {
            WARNING_PRINT("Can't get wallet data. You need to start xcash rpc wallet service before");
            return false;
        }


        if (!get_sync_nodes_majority_list_top(&nodes_majority_list, &nodes_majority_count)) {
            WARNING_PRINT("Could not get data majority nodes sync list");
        }else{
            show_majority_statistics(nodes_majority_list, nodes_majority_count);

            if ((nodes_majority_count < NETWORK_DATA_NODES_VALID_AMOUNT)) {
                INFO_PRINT_STATUS_FAIL("Not enough data majority. Nodes: [%ld/%d]", nodes_majority_count, NETWORK_DATA_NODES_VALID_AMOUNT);
                result = false;
            } else {
                INFO_PRINT_STATUS_OK("Data majority reached. Nodes: [%ld/%d]",  nodes_majority_count, NETWORK_DATA_NODES_VALID_AMOUNT);
                int sync_source_index = get_random_majority(nodes_majority_list, nodes_majority_count);
                result = initial_sync_node(&nodes_majority_list[sync_source_index]);
            }
        }
        free(nodes_majority_list);

        if (!result) {
            INFO_STAGE_PRINT("Waiting for network recovery...");
            sleep(10);
        };
    }
    if (result) {
        INFO_PRINT_STATUS_OK("Database successfully synced")
    }

    return result;
}