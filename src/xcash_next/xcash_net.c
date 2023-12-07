#include "xcash_net.h"
#include "xcash_message.h"

#include "variables.h"
#include "network_functions.h"

#include "uv_net.h"

// FIXME: add support for NONRETURN messages to not mark them as INCOMPLETE
// TODO fix message format
// remove |END| suffix from message. fkng format
// FIXME if there is no ender, the message will be not null terminated
void remove_enders(response_t **responses) {
    int i = 0;
    while (responses && responses[i]) {
        if (responses[i]->status == STATUS_OK) {
            if (responses[i]->size == 0) {
                responses[i]->status = STATUS_INCOMPLETE;
                // FIXME wtf is this
                DEBUG_PRINT("Returned data from host '%s' is empty. Marked it as STATUS_INCOMPLETE", responses[i]->host);
            }else{
                bool ender_found = false;
                char* tmp =  calloc(responses[i]->size+1,1);
                memcpy(tmp,responses[i]->data, responses[i]->size);
                if (responses[i]->size >=sizeof(SOCKET_END_STRING)-1) {
                    char* ender_position = strstr(tmp,SOCKET_END_STRING);
                    if (ender_position) {
                        ender_found = true;
                        int ender_pos = ender_position - tmp;

                        responses[i]->data[ender_pos] = '\0';
                        responses[i]->size = strlen(responses[i]->data);
                    }
                }
                if (!ender_found) {
                    WARNING_PRINT("Returned data has no |END| data size %ld, message:  %s",responses[i]->size, tmp);
                }
                free(tmp);
            }
        }
        i++;
    }
}

/// @brief Sends 'message' data to 'dest' predefined group. Don't forget to use cleanup_reply(...) function in any case of return
/// @param dest Predefined group of receivers. XNET_SEEDS_ALL...
/// @param message message string
/// @param reply pointer to variable that will have pointer to array of xnet_reply_t if result of function call is true. 
/// @return true - The result was OK and reply contains pointer to array of xnet_reply_t. false - something happened
bool xnet_send_data_multi(xcash_dest_t dest, const char* message, response_t ***reply) {
    bool result = false;
    if (!reply) {
        DEBUG_PRINT("reply parameter can't be NULL")
        return false;
    }
        
    switch (dest)
    {
    case XNET_SEEDS_ALL:
    {
        const char *hosts[NETWORK_DATA_NODES_AMOUNT+1];
        int i = 0;
        while (i<NETWORK_DATA_NODES_AMOUNT) {
            hosts[i] = network_data_nodes_list.network_data_nodes_IP_address[i];
            i++;
        }
        hosts[i] = NULL;

        // TODO fix the fkng message format
        int message_buf_size = strlen(message) + strlen(SOCKET_END_STRING) +1;
        char *message_ender = calloc(message_buf_size, 1);
        snprintf(message_ender, message_buf_size, "%s%s",message, SOCKET_END_STRING);

        response_t **responses = send_multi_request(hosts, XCASH_DPOPS_PORT, message_ender);
        free(message_ender);

        if (responses) {
            remove_enders(responses);
            result = true;
        }

        *reply = responses;
    }
        break;
    case XNET_SEEDS_ALL_ONLINE:
    {
        const char *hosts[NETWORK_DATA_NODES_AMOUNT+1];
        int si = 0, di = 0;
        while (si<NETWORK_DATA_NODES_AMOUNT) {
            if (network_data_nodes_list.online_status[si]==1) {
                hosts[di] = network_data_nodes_list.network_data_nodes_IP_address[si];
                di++;
            }
            si++;
        }
        hosts[di] = NULL;

        // TODO fix the fkng message format
        int message_buf_size = strlen(message) + strlen(SOCKET_END_STRING) +1;
        char *message_ender = malloc(message_buf_size);
        snprintf(message_ender, message_buf_size, "%s%s",message, SOCKET_END_STRING);

        response_t **responses = send_multi_request(hosts, XCASH_DPOPS_PORT, message_ender);
        free(message_ender);

        if (responses) {
            remove_enders(responses);
            result = true;
        }

        *reply = responses;
        break;
    }
    case XNET_DELEGATES_ALL: {
        const char* hosts[BLOCK_VERIFIERS_TOTAL_AMOUNT+1];

        // TODO Maybe need to revise this.  BLOCK_VERIFIERS_AMOUNT because there is no reason to check nodes out of active list
        size_t host_index = 0;
        for (size_t i = 0; i < BLOCK_VERIFIERS_AMOUNT; i++)
        {
            if (strlen(delegates_all[i].IP_address) != 0) {
                DEBUG_PRINT("REQ to %s : %s", delegates_all[i].delegate_name, delegates_all[i].IP_address);
                hosts[host_index++] = delegates_all[i].IP_address;
            }
        }
        hosts[host_index++] =  NULL;

        // TODO fix the fkng message format
        int message_buf_size = strlen(message) + strlen(SOCKET_END_STRING) +1;
        char *message_ender = calloc(message_buf_size, 1);
        snprintf(message_ender, message_buf_size, "%s%s",message, SOCKET_END_STRING);

        response_t **responses = send_multi_request(hosts, XCASH_DPOPS_PORT, message_ender);
        free(message_ender);

        if (responses) {
            remove_enders(responses);
            result = true;
        }

        *reply = responses;
        break;
    }
    case XNET_DELEGATES_ALL_ONLINE: {
        const char* hosts[BLOCK_VERIFIERS_TOTAL_AMOUNT+1];

        // TODO Maybe need to revise this.  BLOCK_VERIFIERS_AMOUNT because there is no reason to check nodes out of active list
        size_t host_index = 0;
        for (size_t i = 0; i < BLOCK_VERIFIERS_AMOUNT; i++)
        {
            //! only online, existing and not myself
            if ((strcmp(delegates_all[i].online_status,"true") == 0) &&  (strlen(delegates_all[i].IP_address) != 0) && (strcmp(delegates_all[i].public_address, xcash_wallet_public_address) != 0)) {
                hosts[host_index++] = delegates_all[i].IP_address;
            }
        }
        hosts[host_index++] =  NULL;

        // TODO fix the fkng message format
        int message_buf_size = strlen(message) + strlen(SOCKET_END_STRING) +1;
        char *message_ender = calloc(message_buf_size, 1);
        snprintf(message_ender, message_buf_size, "%s%s",message, SOCKET_END_STRING);

        response_t **responses = send_multi_request(hosts, XCASH_DPOPS_PORT, message_ender);
        free(message_ender);

        if (responses) {
            remove_enders(responses);
            result = true;
        }

        *reply = responses;
        break;
    }

    default:
        break;
    }


    return result;
}


bool send_message_param_list(xcash_dest_t dest, xcash_msg_t msg, response_t ***reply, const char** pair_params) {
    bool result = false;
    *reply = NULL;

    char* message_data = create_message_param_list(msg, pair_params);

    if (!message_data){
        return false;
    }

    result = xnet_send_data_multi(dest, message_data, reply);

    free(message_data);
    return result;
}


bool send_message_param(xcash_dest_t dest, xcash_msg_t msg, response_t ***reply, ...) {
    bool result = false;
    char* message_data = NULL;
    *reply = NULL;


    va_list args;

    va_start(args, reply);
    message_data = create_message_args(msg, args);
    va_end(args);


    if (!message_data){
        return false;
    }

    result = xnet_send_data_multi(dest, message_data, reply);

    free(message_data);
    return result;
}



bool send_message(xcash_dest_t dest, xcash_msg_t msg, response_t ***reply) {
    bool result = false;
    *reply = NULL;
    char* message_data = create_message(msg);

    if (!message_data){
        return false;
    }

    result = xnet_send_data_multi(dest, message_data, reply);

    free(message_data);
    return result;
}

bool send_direct_message_param_list(const char* host, xcash_msg_t msg, response_t ***reply, const char** pair_params) {
    bool result = false;
    *reply = NULL;

    const char *hosts[] = {host, NULL};

    char* message_data = create_message_param_list(msg, pair_params);

    if (!message_data){
        return false;
    }


    // TODO fix the fkng message format
    int message_buf_size = strlen(message_data) + strlen(SOCKET_END_STRING) +1;
    char *message_ender = malloc(message_buf_size);
    snprintf(message_ender, message_buf_size, "%s%s",message_data, SOCKET_END_STRING);

    response_t **responses = send_multi_request(hosts, XCASH_DPOPS_PORT, message_ender);
    free(message_ender);

    if (responses) {
        remove_enders(responses);
        result = true;
    }

    *reply = responses;

    free(message_data);
    return result;

}



bool send_direct_message_param(const char* host, xcash_msg_t msg, response_t ***reply, ...) {
    bool result = false;
    char* message_data = NULL;
    *reply = NULL;

    const char *hosts[] = {host, NULL};

    va_list args;

    va_start(args, reply);
    message_data = create_message_args(msg, args);
    va_end(args);

    if (!message_data){
        return false;
    }

    // TODO fix the fkng message format
    int message_buf_size = strlen(message_data) + strlen(SOCKET_END_STRING) +1;
    char *message_ender = malloc(message_buf_size);
    snprintf(message_ender, message_buf_size, "%s%s",message_data, SOCKET_END_STRING);

    response_t **responses = send_multi_request(hosts, XCASH_DPOPS_PORT, message_ender);
    free(message_ender);

    if (responses) {
        remove_enders(responses);
        result = true;
    }

    *reply = responses;


    // result = true;

    free(message_data);
    return result;
}


bool send_direct_message(const char* host, xcash_msg_t msg, response_t ***reply) {
    bool result = false;

    result = send_direct_message_param(host, msg, reply, NULL);

    return result;
}