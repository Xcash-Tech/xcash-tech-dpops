#include "xcash_message.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "network_security_functions.h"
#include "variables.h"

const char* xcash_net_messages[] = {
    "NODE_TO_BLOCK_VERIFIERS_ADD_RESERVE_PROOF",
    "NODES_TO_BLOCK_VERIFIERS_REGISTER_DELEGATE",
    "NODE_TO_NETWORK_DATA_NODES_CHECK_VOTE_STATUS",
    "NODES_TO_BLOCK_VERIFIERS_UPDATE_DELEGATE",
    "NODES_TO_BLOCK_VERIFIERS_RECOVER_DELEGATE",
    "NODE_TO_BLOCK_VERIFIERS_GET_RESERVE_BYTES_DATABASE_HASH",
    "BLOCK_VERIFIERS_TO_NODES_RESERVE_BYTES_DATABASE_SYNC_CHECK_ALL_DOWNLOAD",
    "GET_CURRENT_BLOCK_HEIGHT",
    "SEND_CURRENT_BLOCK_HEIGHT",
    "MAIN_NODES_TO_NODES_PART_4_OF_ROUND_CREATE_NEW_BLOCK",
    "MAIN_NETWORK_DATA_NODE_TO_BLOCK_VERIFIERS_START_BLOCK",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_VRF_DATA",
    "NODES_TO_NODES_VOTE_MAJORITY_RESULTS",
    "NODES_TO_NODES_VOTE_RESULTS",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_BLOCK_BLOB_SIGNATURE",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_INVALID_RESERVE_PROOFS",
    "NODE_TO_NETWORK_DATA_NODES_GET_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST",
    "NODE_TO_NETWORK_DATA_NODES_GET_CURRENT_BLOCK_VERIFIERS_LIST",
    "NETWORK_DATA_NODE_TO_NODE_SEND_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST",
    "NETWORK_DATA_NODE_TO_NODE_SEND_CURRENT_BLOCK_VERIFIERS_LIST",
    "BLOCK_VERIFIERS_TO_NETWORK_DATA_NODE_BLOCK_VERIFIERS_CURRENT_TIME",
    "NETWORK_DATA_NODE_TO_BLOCK_VERIFIERS_BLOCK_VERIFIERS_CURRENT_TIME",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_ONLINE_STATUS",
    "NODE_TO_BLOCK_VERIFIERS_CHECK_IF_CURRENT_BLOCK_VERIFIER",
    "BLOCK_VERIFIERS_TO_NODE_SEND_RESERVE_BYTES",
    "NETWORK_DATA_NODES_TO_NETWORK_DATA_NODES_DATABASE_SYNC_CHECK",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_SYNC_CHECK_ALL_UPDATE",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_SYNC_CHECK_ALL_DOWNLOAD",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_SYNC_CHECK_DOWNLOAD",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_DOWNLOAD_FILE_UPDATE",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_DOWNLOAD_FILE_DOWNLOAD",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_SYNC_CHECK_ALL_UPDATE",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_SYNC_CHECK_ALL_DOWNLOAD",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_DOWNLOAD_FILE_UPDATE",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_DOWNLOAD_FILE_DOWNLOAD",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_SYNC_CHECK_UPDATE",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_SYNC_CHECK_DOWNLOAD",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_DOWNLOAD_FILE_UPDATE",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_DOWNLOAD_FILE_DOWNLOAD",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_SYNC_CHECK_UPDATE",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_SYNC_CHECK_DOWNLOAD",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_DOWNLOAD_FILE_UPDATE",
    "BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_DOWNLOAD_FILE_DOWNLOAD",
    "XCASH_GET_SYNC_INFO",
    "XCASH_GET_BLOCK_PRODUCERS",
    "XCASH_GET_BLOCK_HASH",

};

const xcash_msg_t WALLET_SIGN_MESSAGES[] = {
    XMSG_NODE_TO_NETWORK_DATA_NODES_GET_PREVIOUS_CURRENT_NEXT_BLOCK_VERIFIERS_LIST,
    XMSG_NODE_TO_BLOCK_VERIFIERS_ADD_RESERVE_PROOF, XMSG_NODES_TO_BLOCK_VERIFIERS_REGISTER_DELEGATE,
    XMSG_NODES_TO_BLOCK_VERIFIERS_UPDATE_DELEGATE, XMSG_NONE};
const size_t WALLET_SIGN_MESSAGES_COUNT = ARRAY_SIZE(WALLET_SIGN_MESSAGES) - 1;

const xcash_msg_t UNSIGNED_MESSAGES[] = {XMSG_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_ONLINE_STATUS,
                                         XMSG_GET_CURRENT_BLOCK_HEIGHT, XMSG_XCASH_GET_SYNC_INFO, XMSG_NONE};
const size_t UNSIGNED_MESSAGES_COUNT = ARRAY_SIZE(UNSIGNED_MESSAGES) - 1;

const xcash_msg_t NONRETURN_MESSAGES[] = {XMSG_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_ONLINE_STATUS,
                                          XMSG_NETWORK_DATA_NODES_TO_NETWORK_DATA_NODES_DATABASE_SYNC_CHECK,
                                          XMSG_SEND_CURRENT_BLOCK_HEIGHT,
                                          XMSG_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_VRF_DATA,
                                          XMSG_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_BLOCK_BLOB_SIGNATURE,
                                          XMSG_NODES_TO_NODES_VOTE_RESULTS,
                                          XMSG_NODES_TO_NODES_VOTE_MAJORITY_RESULTS,
                                          XMSG_MAIN_NODES_TO_NODES_PART_4_OF_ROUND_CREATE_NEW_BLOCK,
                                          XMSG_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_INVALID_RESERVE_PROOFS,
                                          XMSG_MAIN_NETWORK_DATA_NODE_TO_BLOCK_VERIFIERS_START_BLOCK,
                                          XMSG_NONE};
const size_t NONRETURN_MESSAGES_COUNT = ARRAY_SIZE(NONRETURN_MESSAGES) - 1;

const xcash_msg_t xcash_db_sync_messages[] = {
    XMSG_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_SYNC_CHECK_UPDATE,
    XMSG_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_SYNC_CHECK_UPDATE,
    XMSG_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_SYNC_CHECK_ALL_UPDATE,
    XMSG_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_SYNC_CHECK_ALL_UPDATE,
};

const xcash_msg_t xcash_db_download_messages[] = {
    XMSG_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_DELEGATES_DATABASE_DOWNLOAD_FILE_UPDATE,
    XMSG_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_STATISTICS_DATABASE_DOWNLOAD_FILE_UPDATE,
    XMSG_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_PROOFS_DATABASE_DOWNLOAD_FILE_UPDATE,
    XMSG_BLOCK_VERIFIERS_TO_BLOCK_VERIFIERS_RESERVE_BYTES_DATABASE_DOWNLOAD_FILE_UPDATE,
};

bool is_unsigned_type(xcash_msg_t msg) {
    for (size_t i = 0; i < UNSIGNED_MESSAGES_COUNT; i++) {
        if (msg == UNSIGNED_MESSAGES[i]) {
            return true;
        }
    }
    return false;
}

bool is_walletsign_type(xcash_msg_t msg) {
    for (size_t i = 0; i < WALLET_SIGN_MESSAGES_COUNT; i++) {
        if (msg == WALLET_SIGN_MESSAGES[i]) {
            return true;
        }
    }
    return false;
}

bool is_nonreturn_type(xcash_msg_t msg) {
    for (size_t i = 0; i < NONRETURN_MESSAGES_COUNT; i++) {
        if (msg == NONRETURN_MESSAGES[i]) {
            return true;
        }
    }
    return false;
}

bool sign_message(char* message_buf, size_t message_buf_size) {
    (void)message_buf_size;
    // TODO: rewrite old sign code
    int result = sign_data(message_buf);
    return result == 1 ? true : false;
}

bool sign_message_by_wallet(char* message_buf, size_t message_buf_size) {
    (void)message_buf_size;
    // TODO: rewrite old sign code
    int result = sign_data(message_buf);
    return result == 1 ? true : false;
}

/**
 * @brief Create a message string. Don't forget to release after using
 *
 * @param msg
 * @param params
 * @return const char*
 */

char* create_message_param_list(xcash_msg_t msg, const char** pair_params) {
    char message_buf[BUFFER_SIZE];
    const char* param_key = NULL;
    const char* param_value = NULL;
    int message_offset = 0;
    // TODO: autodetect message json or | separated

    memset(message_buf, 0, sizeof(message_buf));
    // first part of message
    sprintf(message_buf, "{\r\n \"message_settings\": \"%s\"", xcash_net_messages[msg]);
    message_offset = strlen(message_buf);

    size_t current_pair_index = 0;
    while ((param_key = pair_params[current_pair_index++]) != NULL) {
        param_value = pair_params[current_pair_index++];
        if (!param_value) {
            DEBUG_PRINT("Wrong parameters count. Something wrong with the message %s", xcash_net_messages[msg]);
            break;
        }
        sprintf(message_buf + message_offset, ",\r\n \"%s\": \"%s\"", param_key, param_value);
        message_offset = strlen(message_buf);
    }

    strcpy(message_buf + message_offset, ",\r\n}");

    if (!is_unsigned_type(msg)) {
        if (!sign_message(message_buf, sizeof(message_buf))) {
            ERROR_PRINT("Can't sign a message %s", xcash_net_messages[msg]);
            return NULL;
        }
        // if (is_walletsign_type(msg)) {
        //     sign_message_by_wallet(message_buf, sizeof(message_buf));
        // }else{
        //     sign_message(message_buf, sizeof(message_buf));
        // }
    }
    return strdup(message_buf);
}

// char* create_message_args(xcash_msg_t msg, va_list args) {
//     char message_buf[BUFFER_SIZE];
//     char* param_key =  NULL;
//     char* param_value =  NULL;
//     int message_offset = 0;
//     // TODO: autodetect message json or | separated

//     // first part of message
//     sprintf(message_buf, "{\r\n \"message_settings\": \"%s\"",xcash_net_messages[msg]);
//     message_offset = strlen(message_buf);

//     while ((param_key = (char*)va_arg(args, char*)) != NULL)
//     {
//         param_value = (char*)va_arg(args, char*);
//         if (!param_value) {
//             DEBUG_PRINT("Wrong parameters count. Something wrong with the message %s", xcash_net_messages[msg]);
//             break;
//         }
//         sprintf(message_buf + message_offset, ",\r\n \"%s\": \"%s\"", param_key, param_value);
//         message_offset = strlen(message_buf);
//     }

//     strcpy(message_buf + message_offset, ",\r\n}");

//     if (!is_unsigned_type(msg)) {
//         if (!sign_message(message_buf, sizeof(message_buf))){
//             ERROR_PRINT("Can't sign a message %s", xcash_net_messages[msg]);
//             return NULL;
//         }
//         // if (is_walletsign_type(msg)) {
//         //     sign_message_by_wallet(message_buf, sizeof(message_buf));
//         // }else{
//         //     sign_message(message_buf, sizeof(message_buf));
//         // }

//     }
//     return strdup(message_buf);
// }

char* create_message_args(xcash_msg_t msg, va_list args) {
    char* message = NULL;
    va_list args2;
    va_copy(args2, args);

    size_t param_count = 0;
    while ((char*)va_arg(args, char*) != NULL) {
        param_count++;
    }
    param_count++;
    // va_end(args);

    const char** param_list = calloc(param_count, sizeof(char*));

    param_count = 0;
    // va_start(args2, msg);
    while ((param_list[param_count++] = (char*)va_arg(args2, char*)) != NULL) {
    };
    va_end(args2);

    message = create_message_param_list(msg, param_list);
    free(param_list);
    return message;
}

char* create_message_param(xcash_msg_t msg, ...) {
    va_list args;
    char* message = NULL;

    va_start(args, msg);
    message = create_message_args(msg, args);
    va_end(args);

    return message;
}

char* create_message(xcash_msg_t msg) { return create_message_param(msg, NULL); }


int split(const char* str, char delimiter, char*** result_elements) {
    int i, k;
    int elemCount = 0;
    for (i = 0; str[i]; i++) {
        if (str[i] == delimiter) {
            elemCount++;
        }
    }

    // make last element NULL
    char** result = calloc(elemCount+1, sizeof(char*));
    if (!result) return -1;

    int startIdx = 0;
    int endIdx = 0;
    for (i = 0; i < elemCount; i++) {
        while (str[endIdx] != delimiter && str[endIdx] != '\0') {
            endIdx++;
        }

        result[i] = malloc(endIdx - startIdx + 1);
        if (!result[i]) {
            for (k = 0; k < i; k++) {
                free(result[k]);
            }
            free(result);
            return -1;
        }

        strncpy(result[i], str + startIdx, endIdx - startIdx);
        result[i][endIdx - startIdx] = '\0';

        endIdx++;
        startIdx = endIdx;
    }

    *result_elements = result;
    return elemCount;
}

void cleanup_char_list(char **element_list) {
    int i=0;
    while (element_list && element_list[i])
    {
        free(element_list[i]);
        i++;
    };
    free(element_list);
}